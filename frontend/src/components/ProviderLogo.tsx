export function ProviderLogo({
  provider,
  size = 20,
}: {
  provider: string;
  size?: number;
}) {
  const p = provider.toLowerCase();

  if (p === "github") {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z" />
      </svg>
    );
  }

  if (p === "gitlab") {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
        <path d="M23.955 13.587l-1.342-4.135-2.664-8.189a.455.455 0 00-.867 0L16.418 9.45H7.582L4.918 1.263a.455.455 0 00-.867 0L1.386 9.452.044 13.587a.924.924 0 00.331 1.023L12 23.054l11.625-8.443a.92.92 0 00.33-1.024" fill="#FC6D26" />
        <path d="M12 23.054l4.418-13.604H7.582L12 23.054z" fill="#E24329" />
        <path d="M12 23.054l-4.418-13.604H1.386L12 23.054z" fill="#FC6D26" />
        <path d="M1.386 9.452L.044 13.587a.924.924 0 00.331 1.023L12 23.054 1.386 9.452z" fill="#FCA326" />
        <path d="M1.386 9.452h6.196L4.918 1.263a.455.455 0 00-.867 0L1.386 9.452z" fill="#E24329" />
        <path d="M12 23.054l4.418-13.604h6.196L12 23.054z" fill="#FC6D26" />
        <path d="M22.614 9.452l1.341 4.135a.924.924 0 01-.331 1.023L12 23.054l10.614-13.602z" fill="#FCA326" />
        <path d="M22.614 9.452h-6.196l2.664-8.189a.455.455 0 01.868 0l2.664 8.189z" fill="#E24329" />
      </svg>
    );
  }

  if (p === "bitbucket") {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
        <path
          d="M.778 1.213a.768.768 0 00-.768.892l3.263 19.81c.084.5.52.873 1.027.873H19.95a.772.772 0 00.77-.646l3.027-20.03a.768.768 0 00-.768-.899L.778 1.213zM14.52 15.53H9.522L8.17 8.466h7.561l-1.211 7.064z"
          fill="#2684FF"
        />
        <path
          d="M21.528 8.466h-5.785l-1.211 7.064H9.522L4.061 21.4a.604.604 0 00.432.187H19.95a.772.772 0 00.77-.646l.808-12.475z"
          fill="url(#bb-g)"
        />
        <defs>
          <linearGradient id="bb-g" x1="19.223" y1="11.262" x2="11.35" y2="20.052" gradientUnits="userSpaceOnUse">
            <stop offset="0.176" stopColor="#0052CC" />
            <stop offset="1" stopColor="#2684FF" />
          </linearGradient>
        </defs>
      </svg>
    );
  }

  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="16 18 22 12 16 6" />
      <polyline points="8 6 2 12 8 18" />
    </svg>
  );
}

export const PROVIDERS = ["github", "gitlab", "bitbucket"] as const;
export type ProviderKey = typeof PROVIDERS[number];

export function providerLabel(p: string): string {
  const labels: Record<string, string> = {
    github: "GitHub",
    gitlab: "GitLab",
    bitbucket: "Bitbucket",
  };
  return labels[p.toLowerCase()] ?? p;
}
