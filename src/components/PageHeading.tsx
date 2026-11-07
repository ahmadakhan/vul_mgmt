import type { ReactNode } from 'react';
import { pages, type PageId } from '../design/pages';

export function PageHeading({
  page,
  children,
  title: customTitle,
}: {
  page: PageId;
  children: ReactNode;
  title?: string;
}) {
  const { section, title, icon: Icon } = pages[page];
  return (
    <div className="ui-page-heading">
      <div className="ui-page-eyebrow">{section}</div>
      <div className="ui-page-title-row">
        <span className="ui-page-icon">
          <Icon size={20} strokeWidth={1.7} aria-hidden="true" />
        </span>
        <h1 id="page-title" tabIndex={-1}>
          {customTitle ?? title}
        </h1>
      </div>
      <p className="ui-page-description">{children}</p>
    </div>
  );
}
