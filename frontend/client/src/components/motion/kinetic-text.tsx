import { type ElementType, Fragment } from "react";
import { cn } from "@/lib/utils";
import { useInView } from "@/hooks/use-in-view";

interface KineticTextProps {
  /** The sentence to animate. Split into words that stagger in on scroll. */
  text: string;
  className?: string;
  as?: ElementType;
  /** ms between consecutive words (default 55). */
  stagger?: number;
  /** ms before the first word starts (default 0). */
  delay?: number;
  /** Re-animate each time it scrolls into view (default false = once). */
  repeat?: boolean;
}

/**
 * Kinetic typography: reveals a sentence word-by-word as it scrolls into view,
 * each word rising + fading in on a staggered delay. Travel is expressed in `em`
 * so it scales with the heading size. The full text is exposed to assistive tech
 * via aria-label while the animated word spans are aria-hidden.
 */
export function KineticText({
  text,
  className,
  as: Tag = "span",
  stagger = 55,
  delay = 0,
  repeat = false,
}: KineticTextProps) {
  const { ref, inView } = useInView({ once: !repeat });
  const words = text.trim().split(/\s+/);

  return (
    <Tag ref={ref} className={cn("inline", className)} aria-label={text}>
      {words.map((word, i) => (
        <Fragment key={i}>
          <span
            aria-hidden
            className="inline-block transition-[opacity,transform] duration-650 ease-expo-out will-change-transform motion-reduce:transition-none"
            style={{
              transitionDelay: `${delay + i * stagger}ms`,
              opacity: inView ? 1 : 0,
              transform: inView ? "none" : "translateY(0.4em)",
            }}
          >
            {word}
          </span>
          {i < words.length - 1 ? " " : ""}
        </Fragment>
      ))}
    </Tag>
  );
}
