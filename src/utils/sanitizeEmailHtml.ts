/**
 * Defence-in-depth sanitizer for server-authored email HTML that the browser
 * renders through `dangerouslySetInnerHTML` (Action Center preview).
 *
 * The server escapes every feed-controlled value before it reaches an email
 * body (see `escapeHtml` in server/advisoryEmail.ts, server/delivery.ts and the
 * template compiler), but the preview pane is the one place raw HTML crosses
 * the trust boundary into the SPA. If any server-side escape regresses — or an
 * operator pastes markup into a custom body override — a script tag, an inline
 * event handler, or a `javascript:` URL would execute inside the authenticated
 * origin. This module strips exactly those vectors while leaving the
 * legitimate presentational markup (tables, inline styles, headings) intact so
 * the preview still looks like the email.
 */
import createDOMPurify from 'dompurify';

const purifier = typeof window === 'undefined' ? null : createDOMPurify(window);
const styleProperties = new Set([
  'color', 'background-color', 'font-family', 'font-size', 'font-weight', 'font-style',
  'line-height', 'text-align', 'text-decoration', 'text-transform', 'letter-spacing',
  'white-space', 'word-break', 'word-wrap', 'overflow-wrap', 'vertical-align',
  'border', 'border-top', 'border-bottom', 'border-left', 'border-right',
  'border-color', 'border-width', 'border-style', 'border-radius', 'border-collapse', 'border-spacing',
  'table-layout', 'display', 'width', 'height', 'max-width', 'max-height', 'min-width', 'min-height',
  'padding', 'padding-top', 'padding-bottom', 'padding-left', 'padding-right',
  'margin', 'margin-top', 'margin-bottom', 'margin-left', 'margin-right',
]);

purifier?.addHook('uponSanitizeAttribute', (_node, attribute) => {
  if (attribute.attrName === 'style') {
    const parsed = document.createElement('span').style;
    parsed.cssText = attribute.attrValue;
    const safe = document.createElement('span').style;
    for (const property of Array.from(parsed)) {
      const value = parsed.getPropertyValue(property);
      if (!styleProperties.has(property) || /url\s*\(|expression\s*\(|@import|\\/i.test(value)) continue;
      if (property.startsWith('margin') && /-|calc\(|var\(/i.test(value)) continue;
      safe.setProperty(property, value);
    }
    attribute.attrValue = safe.cssText;
  }
  if (attribute.attrName === 'src' && !/^data:image\/(?:png|jpeg|gif|webp);base64,[A-Za-z0-9+/=\s]+$/i.test(attribute.attrValue))
    attribute.keepAttr = false;
  if (attribute.attrName === 'href') {
    try {
      const url = new URL(attribute.attrValue, window.location.href);
      if (!['https:', 'http:', 'mailto:'].includes(url.protocol) || url.username || url.password)
        attribute.keepAttr = false;
    } catch { attribute.keepAttr = false; }
  }
});

purifier?.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'A') node.setAttribute('rel', 'noopener noreferrer');
});

export function sanitizeEmailHtml(html: string): string {
  if (!html || !purifier) return '';
  return purifier.sanitize(html, {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ['style', 'script', 'iframe', 'object', 'embed', 'link', 'meta', 'base', 'form', 'input', 'button', 'textarea', 'select', 'video', 'audio', 'source'],
    FORBID_ATTR: ['srcset', 'background', 'id', 'class', 'name', 'srcdoc', 'formaction', 'action'],
    ALLOW_DATA_ATTR: false,
    ADD_ATTR: ['target'],
    SANITIZE_NAMED_PROPS: true,
    RETURN_TRUSTED_TYPE: false,
  });
}
