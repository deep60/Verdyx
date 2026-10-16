import { type ElementType, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { useInView } from "@/hooks/use-in-view";

interface RevealProps {
  children: ReactNode;
  className?: string;
  /** Rendered element/tag (default div). */
  as?: ElementType;
  /** Delay before the animation starts, in ms — use to stagger siblings. */
  delay?: number;
  /** Vertical travel distance in px (default 24). */
  y?: number;
  /** Re-animate every time it scrolls into view (default false = once). */
  repeat?: boolean;
}

/**
 * Fades + slides its children in when scrolled into view. The building block
 * for scroll-triggered section reveals. Honors prefers-reduced-motion (the
 * hook reports in-view immediately, and global CSS zeroes the transition).
 */
export function Reveal({
  children,
  className,
  as: Tag = "div",
  delay = 0,
  y = 24,
  repeat = false,
}: RevealProps) {
  const { ref, inView } = useInView({ once: !repeat });

  return (
    <Tag
      ref={ref}
      className={cn(
        "transition-[opacity,transform] duration-650 ease-expo-out will-change-transform motion-reduce:transition-none",
        className
      )}
      style={{
        transitionDelay: `${delay}ms`,
        opacity: inView ? 1 : 0,
        transform: inView ? "none" : `translateY(${y}px)`,
      }}
    >
      {children}
    </Tag>
  );
}
