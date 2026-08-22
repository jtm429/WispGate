# Errors

Transport errors are explicit JSON responses such as `invalid_envelope`, `recipient_offline`, `invalid_auth_proof`, and `endpoint_pending`. Application callback failures are represented as operation/application errors and logged by the runtime. They must never be converted into generic model/LLM errors.

A failed recipient must not silently delete durable Wisp registration or destroy the healthy source session.
