import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import { installDirectApi } from "./lib/api-origin";

installDirectApi();

createRoot(document.getElementById("root")!).render(<App />);
