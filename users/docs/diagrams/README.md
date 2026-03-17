# PlantUML Diagrams — Users API

Seven diagrams covering the full application. Open each `.puml` file with the
[PlantUML extension for VS Code](https://marketplace.visualstudio.com/items?itemName=jebbs.plantuml)
(`Alt+D` to preview) or paste them into [https://www.plantuml.com/plantuml/uml/](https://www.plantuml.com/plantuml/uml/).

| # | File | Diagram Type | What it shows |
|---|------|-------------|---------------|
| 1 | `01_architecture.puml` | **Architecture** | Full AWS infrastructure: API Gateway, Cognito Authorizer, Lambda, DynamoDB, CloudWatch, SNS |
| 2 | `02_sequence_register.puml` | **Sequence** | `POST /users` — registration flow with Cognito rollback on DynamoDB failure |
| 3 | `03_sequence_verify_login.puml` | **Sequence** | `POST /users/verify` (email confirmation) & `POST /users/login` (token issuance) |
| 4 | `04_sequence_protected_routes.puml` | **Sequence** | `GET /users`, `GET /users/{userid}`, `PUT /users/{userid}`, `DELETE /users/{userid}` with JWT auth & ownership checks |
| 5 | `05_class_lambda_internals.puml` | **Class** | Internal structure of `users.py`: functions, AWS clients, env vars, route handlers |
| 6 | `06_activity_flow.puml` | **Activity** | Complete `lambda_handler` decision flow for all 7 routes |
| 7 | `07_state_user_lifecycle.puml` | **State** | User account lifecycle: Unregistered → PendingVerification → Verified → LoggedIn → Deleted |
| 8 | `08_component_observability.puml` | **Component** | CloudWatch custom metrics, built-in Lambda metrics, alarms, dashboard & SNS notifications |
