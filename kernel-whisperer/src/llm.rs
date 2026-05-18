use crate::filter::CrashContext;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WhisperResult {
    pub root_cause_syscall: Option<String>,
    pub explanation:        String,
    pub suggested_fix:      String,
    pub confidence:         String,
}

// HTTP request body — internal, not pub
#[derive(serde::Serialize)]
struct LlmRequest {
    model:       String,
    messages:    Vec<LlmMessage>,
    temperature: f32,
    max_tokens:  u32,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LlmMessage {
    role:    String,
    content: String,
}

// HTTP response — internal, not pub  
#[derive(serde::Deserialize)]
struct LlmResponse {
    choices: Vec<LlmChoice>,
}

#[derive(serde::Deserialize)]
struct LlmChoice {
    message: LlmMessage,
}

pub async fn query_llm(
    ctx: &CrashContext,
    endpoint: &str,
) -> anyhow::Result<WhisperResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {}", e))?;

    let request_body = LlmRequest {
        model: "local".to_string(),
        messages: vec![
            LlmMessage {
                role: "system".to_string(),
                content: crate::prompt::SYSTEM_PROMPT.to_string(),
            },
            LlmMessage {
                role: "user".to_string(),
                content: crate::prompt::format_context(ctx),
            },
        ],
        temperature: 0.1,
        max_tokens: 512,
    };

    let url = format!("{}/v1/chat/completions", endpoint.trim_end_matches('/'));

    let response = client
        .post(&url)
        .json(&request_body)
        .send()
        .await;

    // FAILURE MODE A
    let response = match response {
        Ok(res) if res.status().is_success() => res,
        _ => return Ok(llm_unavailable_result()),
    };

    // FAILURE MODE B
    let response_body = match response.json::<LlmResponse>().await {
        Ok(json) => json,
        Err(e) => {
            tracing::warn!("LLM returned non-JSON response: {}", e);
            return Ok(llm_unavailable_result());
        }
    };

    // FAILURE MODE C
    if response_body.choices.is_empty() {
        return Ok(llm_unavailable_result());
    }

    let raw_text = &response_body.choices[0].message.content;
    let parsed = parse_whisper_result(raw_text, &ctx.confidence);
    Ok(sanitize_with_evidence(parsed, ctx))
}

fn llm_unavailable_result() -> WhisperResult {
    WhisperResult {
        root_cause_syscall: None,
        explanation: "LLM server unavailable. To enable AI \
                     explanations, run: llama-server \
                     -hf ggml-org/gemma-3-1b-it-GGUF \
                     --port 8080".to_string(),
        suggested_fix: "Start the llama-server command shown \
                       above, then retry.".to_string(),
        confidence: "low".to_string(),
    }
}

fn parse_whisper_result(text: &str, fallback_confidence: &str) -> WhisperResult {
    let mut root_cause = None;
    let mut explanation = String::new();
    let mut suggested_fix = String::new();
    let mut confidence = fallback_confidence.to_string();

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("ROOT_CAUSE_SYSCALL: ") {
            root_cause = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("EXPLANATION: ") {
            explanation = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("SUGGESTED_FIX: ") {
            suggested_fix = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("CONFIDENCE: ") {
            let c = rest.trim().to_lowercase();
            if ["high", "medium", "low"].contains(&c.as_str()) {
                confidence = c;
            }
        }
    }

    if explanation.is_empty() {
        explanation = text.trim().to_string();
        suggested_fix = "See explanation above.".to_string();
        root_cause = None;
    }

    WhisperResult {
        root_cause_syscall: root_cause,
        explanation,
        suggested_fix,
        confidence,
    }
}

fn sanitize_with_evidence(
    mut result: WhisperResult,
    ctx: &CrashContext,
) -> WhisperResult {
    let known_roots: Vec<String> = ctx
        .error_syscalls
        .iter()
        .map(|e| {
            let code = e.error.as_ref().map(|x| x.code.as_str()).unwrap_or("?");
            format!("{}({})", e.syscall_name, e.display_arg()) + &format!(" -> {}", code)
        })
        .collect();

    if let Some(root) = &result.root_cause_syscall {
        let lower = root.to_lowercase();
        let is_unknown = lower.contains("unknown") || lower.contains("sigsegv");
        let matches_evidence = known_roots.iter().any(|k| root.contains(k));
        if !is_unknown && !matches_evidence {
            result.root_cause_syscall = ctx.deterministic.root_cause_syscall.clone();
            result.explanation = ctx.deterministic.explanation.clone();
            result.suggested_fix = ctx.deterministic.suggested_fix.clone();
        }
    } else {
        result.root_cause_syscall = ctx.deterministic.root_cause_syscall.clone();
    }

    if result.explanation.trim().is_empty() {
        result.explanation = ctx.deterministic.explanation.clone();
    }
    if result.suggested_fix.trim().is_empty() {
        result.suggested_fix = ctx.deterministic.suggested_fix.clone();
    }
    if !["high", "medium", "low"].contains(&result.confidence.as_str()) {
        result.confidence = ctx.confidence.clone();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{CrashContext, DeterministicDiagnosis};
    use crate::tracer::{SyscallError, SyscallEvent};

    fn test_event(name: &str, args: Vec<&str>, code: Option<&str>, retval: i64) -> SyscallEvent {
        SyscallEvent {
            pid: 1,
            tid: 1,
            syscall_name: name.to_string(),
            args: args.into_iter().map(|s| s.to_string()).collect(),
            return_value: retval,
            error: code.map(|c| SyscallError {
                code: c.to_string(),
                description: "test".to_string(),
            }),
            timestamp_ns: 0,
            duration_ns: None,
            repeat_count: 1,
        }
    }

    fn test_ctx() -> CrashContext {
        CrashContext {
            process_name: "app".to_string(),
            exit_signal: None,
            exit_code: Some(1),
            runtime_ms: 10,
            total_syscalls: 2,
            error_syscalls: vec![test_event(
                "openat",
                vec!["AT_FDCWD", "/etc/missing.conf"],
                Some("ENOENT"),
                -1,
            )],
            last_n_syscalls: vec![],
            unique_files_accessed: vec!["/etc/missing.conf".to_string()],
            unique_addresses_connected: vec![],
            confidence: "high".to_string(),
            deterministic: DeterministicDiagnosis {
                root_cause_syscall: Some("openat(/etc/missing.conf) -> ENOENT".to_string()),
                explanation: "deterministic explanation".to_string(),
                suggested_fix: "deterministic fix".to_string(),
            },
        }
    }

    #[test]
    fn parse_whisper_result_parses_structured_output() {
        let txt = "ROOT_CAUSE_SYSCALL: openat(/etc/missing.conf) -> ENOENT\nEXPLANATION: Missing file.\nSUGGESTED_FIX: touch /etc/missing.conf\nCONFIDENCE: high";
        let r = parse_whisper_result(txt, "low");
        assert_eq!(
            r.root_cause_syscall.as_deref(),
            Some("openat(/etc/missing.conf) -> ENOENT")
        );
        assert_eq!(r.explanation, "Missing file.");
        assert_eq!(r.suggested_fix, "touch /etc/missing.conf");
        assert_eq!(r.confidence, "high");
    }

    #[test]
    fn sanitize_with_evidence_rejects_unbacked_root_cause() {
        let ctx = test_ctx();
        let llm = WhisperResult {
            root_cause_syscall: Some("connect(127.0.0.1:5432) -> ECONNREFUSED".to_string()),
            explanation: "network is down".to_string(),
            suggested_fix: "restart database".to_string(),
            confidence: "high".to_string(),
        };
        let out = sanitize_with_evidence(llm, &ctx);
        assert_eq!(
            out.root_cause_syscall.as_deref(),
            Some("openat(/etc/missing.conf) -> ENOENT")
        );
        assert_eq!(out.explanation, "deterministic explanation");
        assert_eq!(out.suggested_fix, "deterministic fix");
    }

    #[test]
    fn sanitize_with_evidence_keeps_backed_root_cause() {
        let ctx = test_ctx();
        let llm = WhisperResult {
            root_cause_syscall: Some("openat(/etc/missing.conf) -> ENOENT".to_string()),
            explanation: "missing config".to_string(),
            suggested_fix: "deploy file".to_string(),
            confidence: "high".to_string(),
        };
        let out = sanitize_with_evidence(llm, &ctx);
        assert_eq!(
            out.root_cause_syscall.as_deref(),
            Some("openat(/etc/missing.conf) -> ENOENT")
        );
        assert_eq!(out.explanation, "missing config");
        assert_eq!(out.suggested_fix, "deploy file");
    }
}
