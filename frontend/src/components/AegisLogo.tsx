export function AegisLogo({
  size = 32,
  className = "",
}: {
  size?: number;
  className?: string;
}) {
  return (
    <svg
      width={size}
      height={Math.round(size * 1.125)}
      viewBox="0 0 40 45"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      <path
        d="M20 2L36 8.5V21C36 31.5 29.5 39.5 20 43C10.5 39.5 4 31.5 4 21V8.5L20 2Z"
        fill="url(#aegis-grad)"
      />
      <path
        d="M20 2L36 8.5V21C36 31.5 29.5 39.5 20 43C10.5 39.5 4 31.5 4 21V8.5L20 2Z"
        stroke="rgba(165,180,252,0.35)"
        strokeWidth="0.75"
        fill="none"
      />
      <path
        d="M22 11L14.5 25H20L17.5 34L26 20H20.5L23.5 11Z"
        fill="white"
        opacity="0.92"
      />
      <defs>
        <linearGradient id="aegis-grad" x1="4" y1="2" x2="36" y2="43" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#6366f1" />
          <stop offset="100%" stopColor="#7c3aed" />
        </linearGradient>
      </defs>
    </svg>
  );
}
