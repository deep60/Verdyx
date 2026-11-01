import { useEffect, useRef, useState, useCallback } from "react";
import { webSocketUrl } from "@/lib/api-origin";

interface WebSocketMessage {
  type: string;
  data: unknown;
}

/**
 * Resilient WebSocket hook.
 *
 * - Keeps the latest `onMessage` callback in a ref so the socket is NOT torn
 *   down and recreated on every render (consumers can pass inline arrows).
 * - Automatically reconnects with exponential backoff when the connection drops.
 */
export function useWebSocket(onMessage?: (message: WebSocketMessage) => void) {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<MessageEvent | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttempts = useRef(0);
  const shouldReconnect = useRef(true);

  // Always point at the freshest callback without re-running the connect effect.
  const onMessageRef = useRef(onMessage);
  useEffect(() => {
    onMessageRef.current = onMessage;
  }, [onMessage]);

  useEffect(() => {
    shouldReconnect.current = true;

    const connect = () => {
      const socket = new WebSocket(webSocketUrl());
      ws.current = socket;

      socket.onopen = () => {
        setIsConnected(true);
        reconnectAttempts.current = 0;
      };

      socket.onclose = () => {
        setIsConnected(false);
        if (shouldReconnect.current) {
          // Exponential backoff capped at 30s.
          const delay = Math.min(1000 * 2 ** reconnectAttempts.current, 30000);
          reconnectAttempts.current += 1;
          reconnectTimer.current = setTimeout(connect, delay);
        }
      };

      socket.onerror = () => {
        socket.close();
      };

      socket.onmessage = (event) => {
        setLastMessage(event);
        try {
          const message = JSON.parse(event.data);
          onMessageRef.current?.(message);
        } catch (error) {
          console.error("Failed to parse WebSocket message:", error);
        }
      };
    };

    connect();

    return () => {
      shouldReconnect.current = false;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      ws.current?.close();
    };
  }, []);

  const sendMessage = useCallback((message: unknown) => {
    if (ws.current?.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(message));
    }
  }, []);

  return { isConnected, sendMessage, lastMessage };
}
