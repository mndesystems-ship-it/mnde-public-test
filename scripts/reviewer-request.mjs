export function reviewerRequest({ requestId, tool, testerId = "TESTER-UNASSIGNED", installationId = "INSTALLATION-UNASSIGNED", parameters = {} }) {
  const toolCall = { tool, priority: 1, ...(Object.keys(parameters).length === 0 ? {} : { parameters }) };
  return {
    execution_request: {
      request_id: requestId,
      submitted_region: "us-west-2",
      actor: { user_id: testerId },
      parameters: { tester_id: testerId, installation_id: installationId },
      resources: { gpu_type: "a10g", gpu_count: 1, hours: 1 },
      execution: { auto_scale: false, max_scale_multiplier: 1, retry_on_fail: false, max_retries: 0 },
      tool_calls: [toolCall],
      orbit_intent: {
        orbit_version: "2.0",
        action: "execute",
        boundary: "reviewer-kit",
        payload: { tool_calls: [toolCall] },
        lifecycle_state: "ARMED",
        signatures: [{ alg: "hmac-sha256", sig: "reviewer-kit" }]
      },
      release_request: { execution_id: requestId, hold_state: "APPROVED", already_consumed: false },
      runtime_observation: {
        kill_switch_active: false,
        actual_gpu_count: 1,
        actual_hours: 1,
        actual_total_cost_cents: 500
      }
    },
    pricing_data: { gpu_hour_cents: 500 }
  };
}
