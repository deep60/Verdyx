interface VerdyxMarkProps {
  size?: number;
  className?: string;
}

export function VerdyxMark({ size = 28, className = "" }: VerdyxMarkProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 240 240"
      width={size}
      height={size}
      fill="none"
      aria-hidden="true"
      className={`shrink-0 ${className}`}
    >
      <rect width="240" height="240" rx="16" fill="#141513" stroke="#32342C" strokeWidth="4" />
      <g stroke="#7A7858" strokeWidth="2.2" opacity="0.85">
        <path d="M18 24H32M25 17V31" />
        <path d="M208 24H222M215 17V31" />
        <path d="M18 216H32M25 209V223" />
        <path d="M208 216H222M215 209V223" />
      </g>
      <rect
        x="30"
        y="30"
        width="180"
        height="180"
        stroke="#7A7858"
        strokeWidth="1.5"
        strokeDasharray="3 4"
        opacity="0.6"
      />
      <g stroke="#ABA658" strokeWidth="2" opacity="0.85">
        <path d="M120 18V36M120 44V68" />
        <path d="M112 52H128M112 60H128" />
        <path d="M18 120H36M204 120H222" />
        <path d="M120 206V222" />
      </g>
      <g stroke="#F3F1EA" strokeWidth="4.2" strokeLinejoin="miter">
        <path d="M44 46L92 128" />
        <path d="M196 46L148 128" />
        <path d="M56 46L99 120" />
        <path d="M184 46L141 120" />
        <path d="M68 46L106 111" />
        <path d="M172 46L134 111" />
        <path d="M80 46L120 116L160 46" />
        <path d="M120 116V144" />
      </g>
      <g stroke="#F0D83A" strokeWidth="4.2" strokeLinejoin="miter">
        <path d="M92 128L120 186L148 128" />
        <path d="M99 120L120 166L141 120" />
        <path d="M106 111L120 144L134 111" />
        <path d="M120 144V186" />
        <path d="M92 128L106 111" />
        <path d="M148 128L134 111" />
      </g>
      <circle cx="120" cy="186" r="10.5" fill="#F0D83A" />
    </svg>
  );
}

interface VerdyxLogoProps {
  size?: number;
  showSubtitle?: boolean;
  textClassName?: string;
  className?: string;
}

export function VerdyxLogo({
  size = 28,
  showSubtitle = false,
  textClassName = "text-[15px]",
  className = "",
}: VerdyxLogoProps) {
  return (
    <span className={`inline-flex items-center gap-2.5 ${className}`}>
      <VerdyxMark size={size} />
      <span className="flex flex-col leading-none">
        <span className={`font-semibold tracking-[0.08em] uppercase ${textClassName}`}>
          VERDYX
        </span>
        {showSubtitle && (
          <span className="mt-1 font-mono text-[9px] uppercase tracking-[0.16em] opacity-70">
            Decentralized Threat Intelligence
          </span>
        )}
      </span>
    </span>
  );
}
