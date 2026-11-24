# Operate native prompt assessment

Enable the native profile only for a policy with a supported input rule set. Tidewall freezes its effective report mode, detector action, failure action, generic malicious-prompt detector, optional malicious and benign lists, and supported access rules. An access rule can inspect the qualified Claude application ID. Activation rejects unsupported controls. A change to the effective snapshot requires a fresh grant. The historical decision records its semantic revision.

## Connect the standalone classifier

Use the released standalone detector with its pinned base, tokenizer and adapter. Reuse an existing verified model directory with `python -m tidewall_lora.prepare --models-from "$MODEL_DIRECTORY" --state "$SERVICE_STATE" --device "$DEVICE"`. The directory containing `service.json` and the generated key is private to the service operator. Launch the detector with that config and check `/health/ready` before enabling the profile. Configure the Server process with the following settings.

| Setting | Value |
| --- | --- |
| `NATIVE_CLASSIFIER_ORIGIN` | Exact classifier origin with no path, query or user information. Use HTTPS for remote service. |
| `NATIVE_CLASSIFIER_TENANT_ID` | The tenant UUID in the selected private service config. |
| `NATIVE_CLASSIFIER_KEY_FILE` | Absolute path to the protected bearer key file readable by the Server. |
| `NATIVE_CLASSIFIER_CA_FILE` | Optional trusted CA bundle for the selected HTTPS endpoint. |
| `NATIVE_CLASSIFIER_ALLOW_LOOPBACK_HTTP` | Set to true only for an explicitly selected literal loopback listener. |
| `NATIVE_CLASSIFIER_TIMEOUT_MS` | 1,200 ms by default, subject to the remaining callback budget. |

Allow only the Server to reach the classifier with its bearer. The device keeps its usual enrolled access credential and the separately issued session capability. These carry no administrative, viewer or model-service authority.

## Grant capture for a selected session

1. A policy administrator sends `PUT /v1/policies/{policy_id}/native-prompt` with `{"enabled":true,"threshold":0.5}`. Record the returned generation and profile.
2. Enroll and approve the Collector. Prepare a fresh, explicitly selected native session and working directory with its installed CLI. Its first preparation returns a keyed session token.
3. Send the device ID, keyed session token, exact native profile and bounded TTL to `POST /v1/native-prompt/grants` under policy-scoped admin authorization. Hand the resulting metadata capability to the installed Collector through a protected descriptor.
4. Run a genuine metadata-only callback. Read its verified Server session ID. Issue a new session grant with `capture_allowed=true` and that ID. Import the grant with the explicit local `--capture` selection. Either permission can be withheld.
5. Revoke a grant with `DELETE /v1/native-prompt/grants/{grant_id}`. To stop local capture, prepare the same selected session without `--capture`. A new session or re-enrollment needs fresh bootstrap and consent.

The prompt travels only in the bounded inline decision, with one complete user message, up to 8,000 UTF-8 bytes and 1,024 templated production tokens. The ordinary metadata queue, raw guard retention, protected-content exports and legacy Collector writes retain their existing contracts.

## Read the evidence

Open the native prompt detail in Sessions or read `GET /v1/agent-sessions/{session_id}/native-prompts` with an authorized viewer. The committed assessment carries the pinned model identity and uncalibrated two-class score only when inference succeeded. An access rule can deny without a model result. During a classifier failure the frozen policy determines the Server action. If Tidewall cannot be reached in time, ordinary Collector fallback is exit zero and empty stdout.

A prepared action describes the Server transaction. The separate reporter stages describe observed output, native acknowledgement and controlled tool effect. Missing stages remain unknown. A native prevention claim requires the correlated stdout, agent acknowledgement and complete zero-effect trace. The Collector checkout's `docs/native-prompt-demo.md` describes the disposable loopback setup and the eight controlled cases. Each Server and model instance should use its own private state during qualification.
