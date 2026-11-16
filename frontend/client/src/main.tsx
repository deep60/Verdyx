import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import { installDirectApi } from "./lib/api-origin";
import { initErrorReporting } from "./lib/error-reporting";

installDirectApi();
void initErrorReporting();

createRoot(document.getElementById("root")!).render(<App />);
