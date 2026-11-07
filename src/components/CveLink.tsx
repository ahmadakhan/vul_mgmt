import React from 'react';

type CveLinkProps = {
  cveId: string;
  className?: string;
};

export function CveLink({ cveId, className = '' }: CveLinkProps) {
  return (
    <a
      href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`}
      target="_blank"
      rel="noopener noreferrer"
      aria-label={`Open ${cveId} on NVD (new tab)`}
      title="View the canonical CVE record on NVD"
      onClick={(event) => event.stopPropagation()}
      className={`font-mono font-semibold text-blue-400 light:text-blue-700 text-sm hover:underline underline-offset-4 rounded focus-visible:outline-2 focus-visible:outline-blue-500 focus-visible:outline-offset-4 ${className}`}
    >
      {cveId}
    </a>
  );
}
