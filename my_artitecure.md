Module 0: AI Model Training (The Brain)

Data Preparation: Load the LMD-2023 full-csv into Pandas, group the rows by ProcessGuid, and sort by UtcTime to create sequential event arrays for each process.

Balancing: Undersample the benign class to perfectly match the ~166,000 malicious sequences, creating a 50/50 training split.

Model Architecture: Build a PyTorch 1D-CNN or GRU sequence classifier that uses an Embedding layer to process Sysmon EventIDs.

ONNX Export: Convert the trained PyTorch (.pt) model to the .onnx format to guarantee millisecond-level CPU inference during deployment.

Module 1: Windows Endpoint Agent (The Muscle)

System Tray Integration: Use pystray to run the .exe silently in the background with a right-click context menu (Pause/Resume Protection).

Process Interceptor & Freeze: Use the wmi library to detect new process launches instantly and psutil.Process(pid).suspend() to freeze them in memory before execution.

Local Whitelist (L1): Calculate the SHA-256 hash of the executable and check it against a local SQLite database of trusted Windows files to bypass cloud latency.

Native UI Alerts: Trigger a customtkinter modal popup when a threat is detected, giving the user options to either "Kill Process" or "Run Anyway".

Module 2: Cloud Backend API (The Dispatcher)

API Gateway: Deploy a FastAPI application to receive asynchronous HTTP POST requests containing process telemetry from the Windows agents.

Inference Engine: Utilize onnxruntime to pass the incoming Sysmon sequence to the exported model and return a verdict in under 10ms.

Module 3: Database & Telemetry (The Memory)

Schema: Use PostgreSQL and SQLAlchemy to store structured telemetry (timestamp, machine IP, process ID, file path, and model confidence score).

Audit Logging: Record user override actions (e.g., logging when a user manually clicks "Run Anyway" on a flagged threat).

Module 4: Web Admin Portal (The Command Center)

Tech Stack: Next.js and TailwindCSS.

Live Dashboard: Poll the PostgreSQL database to display a real-time feed of active threats and connected endpoints.

Action Panel: Display the sequence of events that led to a specific alert, allowing a security admin to analyze the process behavior visually.