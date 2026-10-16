import { useEffect, useRef } from "react";

type Vec3 = { x: number; y: number; z: number };

function project(p: Vec3, rotX: number, rotY: number, cx: number, cy: number, scale: number) {
  const cosY = Math.cos(rotY);
  const sinY = Math.sin(rotY);
  const x1 = p.x * cosY - p.z * sinY;
  const z1 = p.x * sinY + p.z * cosY;
  const cosX = Math.cos(rotX);
  const sinX = Math.sin(rotX);
  const y2 = p.y * cosX - z1 * sinX;
  const z2 = p.y * sinX + z1 * cosX;
  const depth = 3.2 + z2;
  const f = scale / depth;
  return { x: cx + x1 * f, y: cy + y2 * f, z: z2, f };
}

export function Scene3D({ className = "" }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let frame = 0;
    let raf = 0;
    let pointerX = 0;
    let pointerY = 0;

    const nodes: Vec3[] = Array.from({ length: 42 }, (_, i) => {
      const t = i / 42;
      const phi = Math.acos(1 - 2 * t);
      const theta = Math.PI * (1 + Math.sqrt(5)) * i;
      return {
        x: Math.sin(phi) * Math.cos(theta),
        y: Math.sin(phi) * Math.sin(theta),
        z: Math.cos(phi),
      };
    });

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = canvas.clientWidth * dpr;
      canvas.height = canvas.clientHeight * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    window.addEventListener("resize", resize);

    const onMove = (event: PointerEvent) => {
      const rect = canvas.getBoundingClientRect();
      pointerX = ((event.clientX - rect.left) / rect.width - 0.5) * 0.6;
      pointerY = ((event.clientY - rect.top) / rect.height - 0.5) * 0.4;
    };
    window.addEventListener("pointermove", onMove);

    const draw = () => {
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      ctx.clearRect(0, 0, w, h);
      const t = reduced ? 0.4 : frame * 0.004;
      const projected = nodes.map((node) =>
        project(node, 0.45 + pointerY, t + pointerX, w * 0.62, h * 0.42, Math.min(w, h) * 0.42),
      );

      ctx.lineWidth = 1;
      for (let i = 0; i < projected.length; i++) {
        for (let j = i + 1; j < projected.length; j++) {
          const a = projected[i];
          const b = projected[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.hypot(dx, dy);
          if (dist > 130) continue;
          const alpha = (1 - dist / 130) * 0.35;
          ctx.strokeStyle = `rgba(167, 139, 250, ${alpha})`;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }

      projected
        .slice()
        .sort((a, b) => a.z - b.z)
        .forEach((point) => {
          const radius = 1.4 + point.f * 0.018;
          ctx.fillStyle = point.z > 0 ? "rgba(244, 114, 182, 0.9)" : "rgba(129, 140, 248, 0.75)";
          ctx.beginPath();
          ctx.arc(point.x, point.y, radius, 0, Math.PI * 2);
          ctx.fill();
        });

      frame += 1;
      if (!reduced) raf = requestAnimationFrame(draw);
    };

    draw();
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", onMove);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className={`pointer-events-none absolute inset-0 h-full w-full ${className}`}
    />
  );
}
