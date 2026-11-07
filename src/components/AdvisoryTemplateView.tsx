import { PageHeading } from './PageHeading';
import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useApp } from '../context/AppContext';
import { copyText } from '../utils/clipboard';
import {
  FileCode,
  Send,
  RotateCcw,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  X,
  Type,
  Palette,
  Stamp,
  Sliders,
  Smartphone,
  Monitor,
  Maximize2,
  Minimize2,
  ZoomIn,
  ZoomOut,
  ArrowUp,
  ArrowDown,
  Eye,
  Code2,
  Download,
  Edit3,
  Hash,
} from 'lucide-react';
import { DEFAULT_TEMPLATE_CUSTOMIZATION } from '../utils/templateCompiler';

export const AdvisoryTemplateView: React.FC = () => {
  const {
    advisoryTemplate,
    customAdvisoryTemplate,
    settings,
    templateCustomization,
    updateTemplateCustomization,
    sendTestEmail,
    saveTemplate,
  } = useApp();

  const [testEmail, setTestEmail] = useState('');
  const [showTestModal, setShowTestModal] = useState(false);
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [saveToast, setSaveToast] = useState(false);
  const [previewDevice, setPreviewDevice] = useState<'desktop' | 'mobile'>('desktop');
  const [copiedToken, setCopiedToken] = useState<string | null>(null);
  const [confirmSave, setConfirmSave] = useState(false);
  const [savingTemplate, setSavingTemplate] = useState(false);
  const [confirmSendTest, setConfirmSendTest] = useState(false);
  const [sendingTest, setSendingTest] = useState(false);

  // Enterprise Live Rendering & Scroll Management
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const previewDate = useRef(
    new Date().toLocaleString('en-GB', {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }),
  ).current;
  const previewId = useRef(
    `${settings.advisoryPrefix}${new Date()
      .toLocaleDateString('en-GB', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
      })
      .replace(new RegExp(' ', 'g'), '')}-PREVIEW`,
  ).current;
  const [iframeHeight, setIframeHeight] = useState<number>(880);
   const [scrollMode, setScrollMode] = useState<'fit' | 'contained'>('fit');
   const [zoomLevel, setZoomLevel] = useState<number>(100);
   const [viewFormat, setViewFormat] = useState<'preview' | 'editor' | 'html'>('preview');
   const [htmlSubView, setHtmlSubView] = useState<'rendered' | 'template'>('template');
   const [showTokensInCanvas, setShowTokensInCanvas] = useState(false);
   const [isFullscreen, setIsFullscreen] = useState(false);
   const [copiedHtml, setCopiedHtml] = useState(false);

   const [customTemplate, setCustomTemplate] = useState<string>('');
   const [isCustomTemplate, setIsCustomTemplate] = useState(false);
   const [editorRef, setEditorRef] = useState<HTMLTextAreaElement | null>(null);

   const handleEnterEditor = () => {
      setCustomTemplate(customAdvisoryTemplate ?? advisoryTemplate);
      setIsCustomTemplate(customAdvisoryTemplate !== null);
     setViewFormat('editor');
   };

   const handleExitEditor = () => {
     if (isCustomTemplate) {
       setCustomTemplate('');
       setIsCustomTemplate(false);
     }
     setViewFormat('preview');
   };

   const handleApplyCustomTemplate = () => {
     const trimmed = customTemplate.trim();
     if (trimmed) {
       setIsCustomTemplate(true);
       setViewFormat('preview');
     }
   };

    const tokenList = [
      '{{severity_header_badge}}',
      '{{severity_badge}}',
      '{{advisory_id}}',
      '{{advisory_title}}',
      '{{dispatch_date}}',
      '{{executive_summary}}',
      '{{cve_id_links}}',
      '{{cve_details}}',
      '{{affected_systems_html}}',
      '{{vendor_products_html}}',
      '{{remediation_steps}}',
      '{{remediation_link}}',
      '{{mitigation_steps}}',
      '{{references_link}}',
      '{{vendor_link}}',
      '{{recommended_actions}}',
    ];

   const handleInsertToken = (token: string) => {
     const el = editorRef;
     if (el) {
       const start = el.selectionStart;
       const end = el.selectionEnd;
       const value = customTemplate;
       setCustomTemplate(value.slice(0, start) + token + value.slice(end));
       const newPos = start + token.length;
       setTimeout(() => {
         el.focus();
         el.setSelectionRange(newPos, newPos);
       }, 0);
     }
   };

  // Active customization tool tab
  const [toolTab, setToolTab] = useState<'typography' | 'colors' | 'stamps' | 'tokens'>('colors');

  // Dynamically sync iframe height to eliminate internal scrollbars and scroll trapping
  const syncIframeHeight = useCallback(() => {
    try {
      const iframe = iframeRef.current;
      if (!iframe) return;
      const doc = iframe.contentDocument || iframe.contentWindow?.document;
      if (doc) {
        const h = Math.max(
          doc.documentElement.scrollHeight,
          doc.body.scrollHeight,
          doc.documentElement.offsetHeight,
          doc.body.offsetHeight,
        );
        if (h > 200) {
          setIframeHeight(h + 24);
        }
      }
    } catch {
      // fallback
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(syncIframeHeight, 100);
    return () => clearTimeout(timer);
  }, [templateCustomization, previewDevice, advisoryTemplate, syncIframeHeight]);

  const scrollToIframeTop = () => {
    try {
      iframeRef.current?.contentWindow?.scrollTo({ top: 0, behavior: 'smooth' });
    } catch {}
  };

  const scrollToIframeBottom = () => {
    try {
      iframeRef.current?.contentWindow?.scrollTo({ top: 99999, behavior: 'smooth' });
    } catch {}
  };

  const handleDownloadHtml = () => {
    const blob = new Blob([getRenderedHtml()], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-advisory-template-${new Date().toISOString().split('T')[0]}.html`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const handleCopyRawHtml = async () => {
    if (await copyText(getRenderedHtml())) {
      setCopiedHtml(true);
      setTimeout(() => setCopiedHtml(false), 2000);
    }
   };

  const getTemplateSource = () => {
    return isCustomTemplate && customTemplate ? customTemplate : advisoryTemplate;
  };

   // Preview-only examples; never substitute an unverified real remediation command.
    const getRenderedHtml = () => {
     const source = isCustomTemplate && customTemplate ? customTemplate : advisoryTemplate;
     return source
       .replace(/{{severity}}/g, 'HIGH')
      .replace(
        /{{severity_header_badge}}/g,
        '<span style="display:inline-block;padding:4px 10px;border-radius:4px;background:#f59e0b;color:#ffffff;font-size:11px;line-height:16px;font-weight:700;letter-spacing:0.5px;">HIGH SEVERITY</span>',
      )
      .replace(
        /{{severity_badge}}/g,
        '<span style="display:inline-block;padding:4px 10px;border-radius:4px;background:#f59e0b;color:#ffffff;font-size:11px;line-height:16px;font-weight:700;letter-spacing:0.5px;">HIGH</span>',
      )
      .replace(/{{advisory_id}}/g, previewId)
      .replace(/{{advisory_title}}/g, 'Example advisory — template preview only')
      .replace(/{{dispatch_date}}/g, previewDate)
      .replace(
        /{{executive_summary}}/g,
        'A high-severity security advisory has been identified affecting assets within the monitored environment. Security teams should assess applicability, determine potential exposure, and prioritize remediation in accordance with established vulnerability management and change control procedures.',
      )
      .replace(
        /{{cve_id_links}}/g,
        '<a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001" style="display:inline-block;margin:0 8px 4px 0;color:#1d4ed8;text-decoration:underline;">CVE-2026-0001</a><a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0002" style="display:inline-block;margin:0 8px 4px 0;color:#1d4ed8;text-decoration:underline;">CVE-2026-0002</a>',
      )
      .replace(
        /{{affected_systems_html}}/g,
        '<div style="margin:0 0 8px;font-size:12px;line-height:19px;color:#334155;">Example inventory asset 1</div>\n<div style="margin:0 0 8px;font-size:12px;line-height:19px;color:#334155;">Example inventory asset 2</div>',
      )
      .replace(
        /{{vendor_products_html}}/g,
        '<div style="margin:0 0 8px;padding:0 0 8px;border-bottom:1px solid #e2e8f0;font-size:12px;line-height:19px;color:#334155;"><strong>VendorCorp - ProductSuite</strong><br>Affected versions: &gt;= 4.2 and &lt; 4.8</div>\n<div style="margin:0 0 8px;padding:0 0 8px;border-bottom:1px solid #e2e8f0;font-size:12px;line-height:19px;color:#334155;"><strong>AnotherVendor - ProductLine</strong><br>Affected versions: 10.1 through 10.4</div>',
      )
      .replace(
        /{{cve_details}}/g,
        '<div style="margin:0 0 16px;padding:16px;border:1px solid #e2e8f0;border-left:4px solid #f59e0b;border-radius:4px;background:#ffffff;"><div style="font-size:14px;font-weight:bold;line-height:20px;"><a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001" style="color:#1d4ed8;text-decoration:underline;">CVE-2026-0001</a></div><p style="margin:8px 0 0;font-size:12px;line-height:19px;color:#334155;">A remotely exploitable vulnerability affects the listed product versions.</p><div style="margin:8px 0 0;font-size:11px;line-height:17px;"><a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001" style="color:#1d4ed8;text-decoration:underline;">NVD</a> &nbsp;·&nbsp; <a href="https://example.com" style="color:#1d4ed8;text-decoration:underline;">Vendor advisory</a></div></div>',
      )
      .replace(
        /{{remediation_steps}}/g,
        '<p style="margin:0 0 10px;font-size:12px;line-height:19px;color:#334155;">Review vendor guidance and validate remediation through your change process.</p><div style="margin:0 0 12px;padding:12px 14px;border:1px solid #e2e8f0;border-radius:4px;background:#ffffff;"><strong><a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001" style="color:#1d4ed8;text-decoration:underline;">CVE-2026-0001</a></strong><ul style="margin:6px 0 0;padding-left:20px;font-size:12px;line-height:19px;color:#334155;"><li>Confirm affected versions with the vendor.</li><li>Apply a tested vendor-supported fix.</li><li>Rescan affected systems and record the outcome.</li></ul><p style="margin:8px 0 0;font-size:12px;"><a href="https://example.com/patch-guidance" style="color:#1d4ed8;text-decoration:underline;">Vendor patch</a></p></div><div style="margin:0 0 12px;padding:12px 14px;border:1px solid #e2e8f0;border-radius:4px;background:#ffffff;"><strong><a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0002" style="color:#1d4ed8;text-decoration:underline;">CVE-2026-0002</a></strong><ul style="margin:6px 0 0;padding-left:20px;font-size:12px;line-height:19px;color:#334155;"><li>Disable the vulnerable feature until the vendor update is deployed.</li><li>Verify service health after remediation.</li></ul></div>',
      )
      .replace(
        /{{mitigation_steps}}/g,
        '<ul>\n<li>Review and limit administrative access to trusted networks.</li>\n<li>Monitor affected services for anomalous activity following the advisory window.</li>\n<li>Apply compensating controls if vendor patches are not yet deployable.</li>\n</ul>',
      )
      .replace(
        /{{recommended_actions}}/g,
        '<ul>\n<li>Inventory all affected systems identified in this advisory.</li>\n<li>Apply vendor patches immediately following your change management process.</li>\n<li>Validate backup, restore, and operational functionality after remediation.</li>\n</ul>',
      )
        .replace(/{{vendor_link}}/g, 'https://example.com')
        .replace(/{{remediation_link}}/g, 'https://example.com/patch-guidance')
        .replace(/{{references_link}}/g, 'https://example.com/vendor-advisory');
    };

  const handleSave = () => {
    setConfirmSave(true);
  };

  const confirmSaveAction = async () => {
    if (savingTemplate) return;
    setSavingTemplate(true);
    try {
      if (!(await saveTemplate(isCustomTemplate ? customTemplate : undefined))) return;
      // The save committed to the server and refresh() reloaded the snapshot.
      // Re-seed the local editor draft from the committed context so the
      // preview renders the server-canonical template (with saved settings /
      // body) rather than a stale pre-save draft.
      //
      // Do NOT read customAdvisoryTemplate / advisoryTemplate here: React has
      // not yet committed the post-save snapshot refresh, so those context
      // values are still stale. For a base-template (settings-only) save,
      // dropping isCustomTemplate lets the next render read the refreshed,
      // settings-embedded advisoryTemplate. For a custom-body save, local
      // customTemplate already equals the saved body, so keep it.
      if (!isCustomTemplate) {
        setCustomTemplate('');
        setIsCustomTemplate(false);
      }
      setViewFormat('preview');
      setConfirmSave(false);
      setSaveToast(true);
      setTimeout(() => setSaveToast(false), 2500);
    } finally {
      setSavingTemplate(false);
    }
  };

  const handleReset = () => {
    setShowResetConfirm(true);
  };

  const confirmReset = () => {
    updateTemplateCustomization(DEFAULT_TEMPLATE_CUSTOMIZATION);
    setShowResetConfirm(false);
  };

  const handleSendTest = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setConfirmSendTest(true);
  };

  const confirmSendTestAction = async () => {
    if (sendingTest) return;
    setSendingTest(true);
    try {
      const rendered = getRenderedHtml();
      const unrenderedTokens = rendered.match(/\{\{[a-z_]+\}\}/g);
      if (unrenderedTokens && unrenderedTokens.length > 0) {
        setTestResult({
          success: false,
          message: `Template has unrendered tokens in preview: ${[...new Set(unrenderedTokens)].join(', ')}. Check the HTML source or token list.`,
        });
        setConfirmSendTest(false);
        return;
      }
      const res = await sendTestEmail(testEmail, false, rendered);
      setTestResult(res);
      setConfirmSendTest(false);
      if (res.success) {
        setTimeout(() => {
          setShowTestModal(false);
          setTestResult(null);
        }, 1500);
      }
    } catch (error) {
      setTestResult({
        success: false,
        message: error instanceof Error ? error.message : 'Test email could not be queued.',
      });
      setConfirmSendTest(false);
    } finally {
      setSendingTest(false);
    }
  };

  const handleCopyToken = async (token: string) => {
    if (await copyText(token)) {
      setCopiedToken(token);
      setTimeout(() => setCopiedToken(null), 1800);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="ui-page-header">
        <PageHeading page="template">
          Design clear, professional security advisories. Preview desktop and mobile layouts, customize your
          branding, then save to apply the template to future notifications.
        </PageHeading>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleReset}
            className="text-xs px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-200 light:hover:bg-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-medium transition flex items-center space-x-1"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Professional Default</span>
          </button>
          <button
            onClick={() => {
              setTestResult(null);
              setShowTestModal(true);
            }}
            disabled={confirmSave || confirmSendTest}
            className="text-xs px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-200 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-semibold transition flex items-center space-x-1.5"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Send Test Email</span>
          </button>
          <button
            onClick={handleSave}
            disabled={confirmSave || confirmSendTest}
            className="text-xs px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition shadow-sm"
          >
            {saveToast ? 'Applied to All Notifications!' : 'Save & Apply to Notifications'}
          </button>
        </div>
      </div>

      {/* Live Controls Toolbar (Direct Customization) */}
      <div className="ui-panel bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 shadow-sm space-y-4 transition-colors">
        {/* Tool Sub-Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800 dark:border-zinc-800 light:border-zinc-200 pb-3">
          <div className="flex min-w-0 max-w-full overflow-x-auto items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-1 rounded-xl">
            <button
              onClick={() => setToolTab('colors')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
                toolTab === 'colors'
                  ? 'bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold'
                  : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
              }`}
            >
              <Palette className="w-3.5 h-3.5" />
              <span>Background &amp; Colors</span>
            </button>

            <button
              onClick={() => setToolTab('typography')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
                toolTab === 'typography'
                  ? 'bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold'
                  : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
              }`}
            >
              <Type className="w-3.5 h-3.5" />
              <span>Font Style &amp; Typography</span>
            </button>

            <button
              onClick={() => setToolTab('stamps')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
                toolTab === 'stamps'
                  ? 'bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold'
                  : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
              }`}
            >
              <Stamp className="w-3.5 h-3.5" />
              <span>Drawing Objects &amp; Stamps</span>
            </button>

            <button
              onClick={() => setToolTab('tokens')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
                toolTab === 'tokens'
                  ? 'bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold'
                  : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
              }`}
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>Dynamic Tokens</span>
            </button>
          </div>

          {/* Device Preview Switcher */}
          <div className="flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-1 rounded-xl">
            <button
              onClick={() => setPreviewDevice('desktop')}
              className={`p-1.5 rounded-lg transition ${
                previewDevice === 'desktop'
                  ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
              title="Desktop View (680px)"
            >
              <Monitor className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPreviewDevice('mobile')}
              className={`p-1.5 rounded-lg transition ${
                previewDevice === 'mobile'
                  ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
              title="Mobile Client View (390px)"
            >
              <Smartphone className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab 1: Colors & Backgrounds */}
        {toolTab === 'colors' && (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div>
              <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5">
                Canvas Background
              </label>
              <div className="flex items-center space-x-2">
                <input
                  type="color"
                  value={templateCustomization.canvasBg}
                  onChange={(e) => updateTemplateCustomization({ canvasBg: e.target.value })}
                  className="w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
                />
                <input
                  type="text"
                  value={templateCustomization.canvasBg}
                  onChange={(e) => updateTemplateCustomization({ canvasBg: e.target.value })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
                />
              </div>
              <div className="flex gap-1.5 mt-2">
                {['#09090b', '#0b0f19', '#18181b', '#f8fafc'].map((c) => (
                  <button
                    key={c}
                    onClick={() => updateTemplateCustomization({ canvasBg: c })}
                    className="w-5 h-5 rounded-md border border-zinc-700"
                    style={{ backgroundColor: c }}
                  />
                ))}
              </div>
            </div>

            <div>
              <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5">
                Card Background
              </label>
              <div className="flex items-center space-x-2">
                <input
                  type="color"
                  value={templateCustomization.cardBg}
                  onChange={(e) => updateTemplateCustomization({ cardBg: e.target.value })}
                  className="w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
                />
                <input
                  type="text"
                  value={templateCustomization.cardBg}
                  onChange={(e) => updateTemplateCustomization({ cardBg: e.target.value })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
                />
              </div>
              <div className="flex gap-1.5 mt-2">
                {['#18181b', '#1e293b', '#27272a', '#ffffff'].map((c) => (
                  <button
                    key={c}
                    onClick={() => updateTemplateCustomization({ cardBg: c })}
                    className="w-5 h-5 rounded-md border border-zinc-700"
                    style={{ backgroundColor: c }}
                  />
                ))}
              </div>
            </div>

            <div>
              <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5">
                Header Banner Bg
              </label>
              <div className="flex items-center space-x-2">
                <input
                  type="color"
                  value={templateCustomization.headerBg}
                  onChange={(e) => updateTemplateCustomization({ headerBg: e.target.value })}
                  className="w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
                />
                <input
                  type="text"
                  value={templateCustomization.headerBg}
                  onChange={(e) => updateTemplateCustomization({ headerBg: e.target.value })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
                />
              </div>
              <div className="flex gap-1.5 mt-2">
                {['#1e293b', '#09090b', '#312e81', '#450a0a'].map((c) => (
                  <button
                    key={c}
                    onClick={() => updateTemplateCustomization({ headerBg: c })}
                    className="w-5 h-5 rounded-md border border-zinc-700"
                    style={{ backgroundColor: c }}
                  />
                ))}
              </div>
            </div>

            <div>
              <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5">
                Accent &amp; Link Color
              </label>
              <div className="flex items-center space-x-2">
                <input
                  type="color"
                  value={templateCustomization.accentColor}
                  onChange={(e) => updateTemplateCustomization({ accentColor: e.target.value })}
                  className="w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
                />
                <input
                  type="text"
                  value={templateCustomization.accentColor}
                  onChange={(e) => updateTemplateCustomization({ accentColor: e.target.value })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
                />
              </div>
              <div className="flex gap-1.5 mt-2">
                {['#3b82f6', '#10b981', '#8b5cf6', '#ef4444'].map((c) => (
                  <button
                    key={c}
                    onClick={() => updateTemplateCustomization({ accentColor: c })}
                    className="w-5 h-5 rounded-md border border-zinc-700"
                    style={{ backgroundColor: c }}
                  />
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Typography */}
        {toolTab === 'typography' && (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div>
              <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5">
                Font Style / Family
              </label>
              <select
                value={templateCustomization.fontFamily}
                onChange={(e) =>
                  updateTemplateCustomization({
                    fontFamily: e.target.value as any,
                  })
                }
                className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-3 py-2 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-medium"
              >
                <option value="sans">Plus Jakarta Sans / Modern</option>
                <option value="mono">JetBrains Mono / Technical</option>
                <option value="serif">Georgia / Editorial Serif</option>
                <option value="system">System Clean / Native</option>
              </select>
            </div>

            <div>
              <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5">
                Heading Font Color
              </label>
              <div className="flex items-center space-x-2">
                <input
                  type="color"
                  value={templateCustomization.headingColor}
                  onChange={(e) => updateTemplateCustomization({ headingColor: e.target.value })}
                  className="w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
                />
                <input
                  type="text"
                  value={templateCustomization.headingColor}
                  onChange={(e) => updateTemplateCustomization({ headingColor: e.target.value })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
                />
              </div>
            </div>

            <div>
              <label className="block text-zinc-400 font-mono mb-1.5">Body Font Color</label>
              <div className="flex items-center space-x-2">
                <input
                  type="color"
                  value={templateCustomization.fontColor}
                  onChange={(e) => updateTemplateCustomization({ fontColor: e.target.value })}
                  className="w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
                />
                <input
                  type="text"
                  value={templateCustomization.fontColor}
                  onChange={(e) => updateTemplateCustomization({ fontColor: e.target.value })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
                />
              </div>
            </div>

            <div>
              <label className="block text-zinc-400 font-mono mb-1.5">Border Style &amp; Radius</label>
              <div className="flex items-center space-x-2">
                <select
                  value={templateCustomization.borderStyle}
                  onChange={(e) => updateTemplateCustomization({ borderStyle: e.target.value as any })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2 py-1.5 text-zinc-200 text-xs flex-1"
                >
                  <option value="solid">Solid Border</option>
                  <option value="dashed">Dashed Border</option>
                  <option value="none">No Border</option>
                </select>
                <select
                  value={templateCustomization.borderRadius}
                  onChange={(e) => updateTemplateCustomization({ borderRadius: e.target.value })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2 py-1.5 text-zinc-200 text-xs"
                >
                  <option value="0px">Sharp (0px)</option>
                  <option value="8px">Round (8px)</option>
                  <option value="12px">Pill (12px)</option>
                  <option value="20px">Curved (20px)</option>
                </select>
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: Drawing Objects & Stamps */}
        {toolTab === 'stamps' && (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 text-xs">
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono">
                  Security Stamp Object
                </label>
                <input
                  type="checkbox"
                  checked={templateCustomization.showStamp}
                  onChange={(e) => updateTemplateCustomization({ showStamp: e.target.checked })}
                  className="rounded border-zinc-700 text-zinc-200"
                />
              </div>
              <input
                type="text"
                value={templateCustomization.badgeStampText}
                onChange={(e) => updateTemplateCustomization({ badgeStampText: e.target.value })}
                placeholder="e.g. OFFICIAL SECURITY BULLETIN"
                disabled={!templateCustomization.showStamp}
                className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-3 py-2 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 disabled:opacity-40 font-mono text-xs"
              />
              <div className="flex items-center space-x-1.5 mt-2">
                <span className="text-[11px] text-zinc-500 font-mono">Presets:</span>
                {['CONFIDENTIAL', 'URGENT ACTION', 'OFFICIAL BULLETIN', 'CSAF VEX'].map((t) => (
                  <button
                    key={t}
                    onClick={() => updateTemplateCustomization({ badgeStampText: t })}
                    className="px-2 py-0.5 rounded bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 text-[10px] font-mono hover:bg-zinc-700"
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5">
                Stamp Color
              </label>
              <div className="flex items-center space-x-2">
                <input
                  type="color"
                  value={templateCustomization.badgeStampColor}
                  onChange={(e) => updateTemplateCustomization({ badgeStampColor: e.target.value })}
                  disabled={!templateCustomization.showStamp}
                  className="w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0 disabled:opacity-40"
                />
                <input
                  type="text"
                  value={templateCustomization.badgeStampColor}
                  onChange={(e) => updateTemplateCustomization({ badgeStampColor: e.target.value })}
                  disabled={!templateCustomization.showStamp}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1 disabled:opacity-40"
                />
              </div>
              <div className="flex gap-1.5 mt-2">
                {['#ef4444', '#f59e0b', '#10b981', '#6366f1'].map((c) => (
                  <button
                    key={c}
                    onClick={() => updateTemplateCustomization({ badgeStampColor: c })}
                    className="w-5 h-5 rounded-md border border-zinc-700"
                    style={{ backgroundColor: c }}
                  />
                ))}
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono">
                  Classification Banner
                </label>
                <input
                  type="checkbox"
                  checked={templateCustomization.showClassificationBanner}
                  onChange={(e) =>
                    updateTemplateCustomization({ showClassificationBanner: e.target.checked })
                  }
                  className="rounded border-zinc-700 text-zinc-200"
                />
              </div>
              <input
                type="text"
                value={templateCustomization.classificationText}
                onChange={(e) => updateTemplateCustomization({ classificationText: e.target.value })}
                disabled={!templateCustomization.showClassificationBanner}
                className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-3 py-2 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 disabled:opacity-40 font-mono text-xs"
              />
              <span className="text-[10px] text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono block mt-1">
                Rendered across the top edge of email notices
              </span>
            </div>
          </div>
        )}

        {/* Tab 4: Dynamic Tokens */}
        {toolTab === 'tokens' && (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono text-[11px] font-medium">
              Click to Copy:
            </span>
            {            [
              '{{severity_header_badge}}',
              '{{severity_badge}}',
              '{{advisory_id}}',
              '{{advisory_title}}',
              '{{severity}}',
              '{{dispatch_date}}',
              '{{executive_summary}}',
              '{{cve_id_links}}',
              '{{affected_systems_html}}',
              '{{vendor_products_html}}',
              '{{cve_details}}',
              '{{remediation_steps}}',
              '{{remediation_link}}',
              '{{mitigation_steps}}',
              '{{references_link}}',
              '{{recommended_actions}}',
              '{{vendor_link}}',
            ].map((token) => (
              <button
                key={token}
                onClick={() => handleCopyToken(token)}
                className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 px-2.5 py-1 rounded-lg text-[11px] font-mono hover:border-zinc-600 transition flex items-center space-x-1"
                title="Click to copy token"
              >
                <span>{token}</span>
                {copiedToken === token && <Check className="w-3 h-3 text-emerald-400" />}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* RENDERED CLIENT PREVIEW: RENAMED TO "HTML template" WITH ENTERPRISE SCROLL ENGINE */}
      <div className="ui-panel bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm space-y-4 transition-colors">
        {/* Studio Control Header */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 pb-3.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="flex items-center space-x-2">
              <FileCode className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
              <h2 className="text-xs font-bold text-zinc-200 dark:text-zinc-200 light:text-zinc-800 uppercase tracking-wider font-mono">
                HTML Template
              </h2>
            </div>

            {/* Live Indicator */}
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950/40 text-emerald-300 border border-emerald-800/60 flex items-center space-x-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>Live Rendering Active</span>
            </span>

            {/* Format Switcher: Visual Preview vs HTML Source */}
            <div className="flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-0.5 rounded-xl ml-2">
              <button
                type="button"
                onClick={() => setViewFormat('preview')}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
                  viewFormat === 'preview'
                    ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                    : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
                }`}
              >
                <Eye className="w-3.5 h-3.5" />
                <span>Visual Canvas</span>
              </button>
              <button
                type="button"
                onClick={handleEnterEditor}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
                  viewFormat === 'editor'
                    ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                    : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
                }`}
              >
                <Edit3 className="w-3.5 h-3.5" />
                <span>Template Editor</span>
              </button>
              <button
                type="button"
                onClick={() => setViewFormat('html')}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
                  viewFormat === 'html'
                    ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                    : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
                }`}
              >
                <Code2 className="w-3.5 h-3.5" />
                <span>HTML Code</span>
              </button>
            </div>
          </div>

          {/* Right Toolbar: Scroll Mode, Zoom, Export & Fullscreen */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Scroll Engine Mode */}
            <div className="flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-0.5 rounded-xl">
              <button
                type="button"
                onClick={() => setScrollMode('fit')}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition ${
                  scrollMode === 'fit'
                    ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm font-semibold'
                    : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
                }`}
                title="Auto-Fit Full Height: Automatically expands iframe height to eliminate inner scrollbars and scroll trapping."
              >
                Auto-Fit Flow
              </button>
              <button
                type="button"
                onClick={() => setScrollMode('contained')}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition ${
                  scrollMode === 'contained'
                    ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm font-semibold'
                    : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
                }`}
                title="Contained Viewport: Fixed 640px height with device frame and quick scroll controls."
              >
                Fixed Viewport
              </button>
            </div>

            {/* Zoom Controls */}
            <div className="flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-0.5 rounded-xl font-mono text-[11px]">
              <button
                type="button"
                onClick={() => setZoomLevel((prev) => Math.max(65, prev - 10))}
                className="p-1 text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"
                title="Zoom Out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <span className="px-1 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 min-w-[34px] text-center">
                {zoomLevel}%
              </span>
              <button
                type="button"
                onClick={() => setZoomLevel((prev) => Math.min(130, prev + 10))}
                className="p-1 text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"
                title="Zoom In"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              {zoomLevel !== 100 && (
                <button
                  type="button"
                  onClick={() => setZoomLevel(100)}
                  className="text-[10px] text-zinc-500 hover:text-zinc-300 dark:text-zinc-500 dark:hover:text-zinc-300 light:text-zinc-600 light:hover:text-zinc-800 px-1 border-l border-zinc-800 dark:border-zinc-800 light:border-zinc-300"
                >
                  Reset
                </button>
              )}
            </div>

            {/* Actions: Copy HTML, Download, Fullscreen */}
            <button
              type="button"
              onClick={handleCopyRawHtml}
              className="p-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 hover:bg-zinc-800 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 transition"
              title="Copy Rendered HTML Code"
            >
              {copiedHtml ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )}
            </button>
            <button
              type="button"
              onClick={handleDownloadHtml}
              className="p-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 hover:bg-zinc-800 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 transition"
              title="Download Advisory HTML File"
            >
              <Download className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={() => setIsFullscreen(true)}
              className="p-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 hover:bg-zinc-800 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 transition"
              title="Fullscreen Template Studio"
            >
               <Maximize2 className="w-3.5 h-3.5" />
             </button>
             <button
               type="button"
               onClick={() => setShowTokensInCanvas(!showTokensInCanvas)}
               className={`p-1.5 rounded-xl flex items-center space-x-1.5 text-xs font-mono transition ${
                 showTokensInCanvas
                   ? 'bg-blue-600/20 border border-blue-600 text-blue-300'
                   : 'bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 hover:bg-zinc-800 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700'
               }`}
               title={showTokensInCanvas ? 'Show rendered preview' : 'Show token placeholders in canvas'}
             >
               <Hash className="w-3.5 h-3.5" />
               <span>Show Tokens</span>
             </button>
           </div>
         </div>

        {/* View Mode 3: Template Editor with Live Preview */}
        {viewFormat === 'editor' ? (
          <div className="ui-panel w-full flex flex-col gap-4 bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 rounded-2xl border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-300 overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2.5 bg-zinc-900/80 border-b border-zinc-800 text-xs font-mono text-zinc-400">
              <span className="flex items-center space-x-2">
                <Edit3 className="w-3.5 h-3.5 text-zinc-400" />
                <span>Template Editor — Live Preview</span>
              </span>
              <div className="flex items-center space-x-1">
                <span className="text-zinc-500">{customTemplate.length} characters</span>
                {isCustomTemplate && (
                  <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" title="Custom template active" />
                )}
              </div>
            </div>

            {/* Token Toolbar */}
            <div className="flex flex-wrap items-center gap-1.5 px-4 py-2 bg-zinc-950 border-b border-zinc-800">
              <span className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono text-[10px]">
                Insert Token:
              </span>
              {tokenList.map((token) => (
                <button
                  key={token}
                  type="button"
                  onClick={() => handleInsertToken(token)}
                  className="bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-200 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 px-2 py-0.5 rounded font-mono text-[10px] hover:border-zinc-600 transition"
                  title={`Insert ${token}`}
                >
                  {token}
                </button>
              ))}
            </div>

            {/* Split View: Editor + Live Preview */}
            <div className="flex-1 flex h-[560px]">
              {/* Left: Code Editor */}
              <div className="w-1/2 border-r border-zinc-800 flex flex-col">
                <div className="flex items-center justify-between px-3 py-1.5 bg-zinc-900/80 border-b border-zinc-800 text-xs font-mono text-zinc-400">
                  <span>Template HTML Source</span>
                </div>
                <textarea
                  ref={setEditorRef}
                  value={customTemplate}
                  onChange={(e) => {
                    setCustomTemplate(e.target.value);
                    setIsCustomTemplate(true);
                  }}
                  onKeyDown={(e) => {
                    if (e.ctrlKey && e.key === 's') {
                      e.preventDefault();
                      handleApplyCustomTemplate();
                    }
                  }}
                  className="flex-1 w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 font-mono text-xs p-3 border-0 resize-none focus:outline-none focus:ring-1 focus:ring-blue-500 overflow-auto"
                  spellCheck={false}
                  placeholder="Edit your advisory template HTML with {{token}} placeholders..."
                />
                <div className="flex items-center justify-end gap-2 px-3 py-2 bg-zinc-900/80 border-t border-zinc-800 text-[10px] text-zinc-500 font-mono">
                  <span>Ctrl+S to apply</span>
                  <button
                    type="button"
                    onClick={handleApplyCustomTemplate}
                    className="px-2.5 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded font-medium transition"
                  >
                    Apply to Preview
                  </button>
                  {isCustomTemplate && (
                    <button
                      type="button"
                      onClick={handleExitEditor}
                      className="px-2.5 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded font-medium transition"
                    >
                      Discard Changes
                    </button>
                  )}
                </div>
              </div>

              {/* Right: Live Preview */}
              <div className="w-1/2 flex flex-col">
                <div className="flex items-center justify-between px-3 py-1.5 bg-zinc-900/80 border-b border-zinc-800 text-xs font-mono text-zinc-400">
                  <span>Live Rendered Preview</span>
                  <div className="flex items-center space-x-1">
                    <span className="text-zinc-500">{getRenderedHtml().length} chars</span>
                  </div>
                </div>
                <div className="flex-1 overflow-auto bg-zinc-950/80">
                  <div className="w-[720px] max-w-full mx-auto py-4">
                    <iframe
                      srcDoc={getRenderedHtml()}
                      onLoad={syncIframeHeight}
                      scrolling="no"
                      style={{
                        height: '500px',
                        width: '100%',
                        display: 'block',
                        border: 'none',
                      }}
                      className="transition-all duration-150"
                      sandbox="allow-same-origin"
                      title="Template Editor Live Preview"
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>
        ) : viewFormat === 'html' ? (
          <div className="bg-zinc-950 border border-zinc-800 rounded-xl overflow-hidden shadow-inner">
            <div className="flex items-center justify-between px-4 py-2.5 bg-zinc-900/80 border-b border-zinc-800 text-xs font-mono text-zinc-400">
              <span className="flex items-center space-x-2">
                <Code2 className="w-3.5 h-3.5 text-zinc-400" />
                <span>Template HTML Source</span>
                <div className="flex items-center space-x-1 bg-zinc-950 border border-zinc-800 rounded-lg ml-4">
                  <button
                    type="button"
                    onClick={() => setHtmlSubView('template')}
                    className={`px-2.5 py-1 rounded-lg text-xs font-medium transition ${
                      htmlSubView === 'template'
                        ? 'bg-blue-600 text-white'
                        : 'text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    Template (with tokens)
                  </button>
                  <button
                    type="button"
                    onClick={() => setHtmlSubView('rendered')}
                    className={`px-2.5 py-1 rounded-lg text-xs font-medium transition ${
                      htmlSubView === 'rendered'
                        ? 'bg-blue-600 text-white'
                        : 'text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    Rendered (preview values)
                  </button>
                </div>
              </span>
              <span>{(htmlSubView === 'template' ? getTemplateSource() : getRenderedHtml()).length} characters</span>
            </div>
            <pre className="p-4 text-xs font-mono text-zinc-300 overflow-x-auto max-h-[640px] leading-relaxed selection:bg-zinc-800">
              <code>{htmlSubView === 'template' ? getTemplateSource() : getRenderedHtml()}</code>
            </pre>
          </div>
        ) : (
          /* View Mode 2: Visual Client Canvas with Enterprise Chrome & Non-Trapping Scrolling */
          <div className="ui-panel w-full flex justify-center py-6 px-2 bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 rounded-2xl border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-300 overflow-x-auto relative">
            {/* Device Container Frame */}
            <div
              className={`transition-all duration-300 shadow-2xl relative ${
                previewDevice === 'desktop'
                  ? 'w-[720px] max-w-full rounded-2xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 overflow-hidden bg-zinc-900'
                  : 'w-[410px] max-w-full rounded-[38px] p-2.5 bg-zinc-900 border-4 border-zinc-700 shadow-2xl'
              }`}
              style={{
                transform: zoomLevel !== 100 ? `scale(${zoomLevel / 100})` : undefined,
                transformOrigin: 'top center',
              }}
            >
              {/* Desktop Browser Chrome */}
              {previewDevice === 'desktop' && (
                <div className="bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-200 border-b border-zinc-800 dark:border-zinc-800 light:border-zinc-300 px-4 py-2.5 flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center space-x-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500/80 inline-block" />
                    <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block" />
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block" />
                  </div>
                  <div className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-white text-zinc-400 dark:text-zinc-400 light:text-zinc-600 px-3 py-1 rounded-lg text-[11px] truncate max-w-md border border-zinc-800/60 dark:border-zinc-800/60 light:border-zinc-300">
                    Email preview
                  </div>
                  <div className="text-[10px] text-zinc-500">680px Canvas</div>
                </div>
              )}

              {/* Mobile Phone Chrome */}
              {previewDevice === 'mobile' && (
                <div className="relative rounded-[32px] overflow-hidden bg-zinc-950 border border-zinc-800">
                  {/* Speaker Notch & Status Bar */}
                  <div className="bg-zinc-950 text-zinc-400 px-6 pt-2 pb-1.5 flex items-center justify-between text-[11px] font-mono border-b border-zinc-800/40">
                    <span>9:41</span>
                    <div className="w-18 h-3.5 bg-zinc-800 rounded-full" />
                    <div className="flex items-center space-x-1">
                      <span>5G</span>
                      <span className="w-2 h-2 rounded-full bg-emerald-400" />
                    </div>
                  </div>
                </div>
              )}

              {/* The Iframe Itself with Scroll-Trap Elimination */}
              <div
                className={`relative bg-zinc-950 ${
                  scrollMode === 'contained' ? 'overflow-y-auto max-h-[640px]' : ''
                }`}
              >
                <iframe
                  ref={iframeRef}
                  title="HTML Template Preview"
                  srcDoc={showTokensInCanvas ? getTemplateSource() : getRenderedHtml()}
                  onLoad={syncIframeHeight}
                  scrolling={scrollMode === 'fit' ? 'no' : 'auto'}
                  style={{
                    height: scrollMode === 'fit' ? `${iframeHeight}px` : '640px',
                    width: '100%',
                    display: 'block',
                    border: 'none',
                    backgroundColor: templateCustomization.canvasBg || '#09090b',
                  }}
                  className="w-full transition-all duration-150"
                  sandbox="allow-same-origin"
                />

                {/* Floating Navigation Controls in Contained Viewport Mode */}
                {scrollMode === 'contained' && (
                  <div className="absolute bottom-4 right-4 flex flex-col space-y-1.5 z-10">
                    <button
                      type="button"
                      onClick={scrollToIframeTop}
                      className="p-2 rounded-xl bg-zinc-900/90 hover:bg-zinc-800 text-zinc-300 border border-zinc-700/80 shadow-lg backdrop-blur-sm transition"
                      title="Scroll to Top of Email"
                    >
                      <ArrowUp className="w-3.5 h-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={scrollToIframeBottom}
                      className="p-2 rounded-xl bg-zinc-900/90 hover:bg-zinc-800 text-zinc-300 border border-zinc-700/80 shadow-lg backdrop-blur-sm transition"
                      title="Scroll to Bottom of Email"
                    >
                      <ArrowDown className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Fullscreen Template Studio Modal */}
      {isFullscreen && (
        <div className="fixed inset-0 z-50 flex flex-col bg-zinc-950/95 backdrop-blur-md p-4 sm:p-6 overflow-hidden">
          <div className="flex items-center justify-between pb-4 border-b border-zinc-800">
            <div className="flex items-center space-x-2">
              <FileCode className="w-5 h-5 text-zinc-300" />
              <h2 className="text-sm font-bold text-zinc-100 font-mono">
                Email Template Studio — Fullscreen Inspection
              </h2>
            </div>
            <div className="flex items-center space-x-2">
              <div className="flex items-center space-x-1 bg-zinc-900 border border-zinc-800 p-0.5 rounded-xl">
                <button
                  type="button"
                  aria-label="Desktop preview"
                  onClick={() => setPreviewDevice('desktop')}
                  className={`p-1.5 rounded-lg text-xs ${previewDevice === 'desktop' ? 'bg-zinc-800 text-white' : 'text-zinc-400'}`}
                >
                  <Monitor className="w-4 h-4" />
                </button>
                <button
                  type="button"
                  aria-label="Mobile preview"
                  onClick={() => setPreviewDevice('mobile')}
                  className={`p-1.5 rounded-lg text-xs ${previewDevice === 'mobile' ? 'bg-zinc-800 text-white' : 'text-zinc-400'}`}
                >
                  <Smartphone className="w-4 h-4" />
                </button>
              </div>
              <button
                type="button"
                aria-label="Close fullscreen preview"
                onClick={() => setIsFullscreen(false)}
                className="p-2 rounded-xl bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 transition"
              >
                <Minimize2 className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto flex justify-center py-6">
            <div
              className={`self-start shrink-0 max-w-full transition-all duration-300 shadow-2xl rounded-2xl overflow-hidden border border-zinc-800 ${
                previewDevice === 'desktop' ? 'w-[720px]' : 'w-[400px]'
              }`}
            >
              <iframe
                title="Fullscreen Preview"
                key={previewDevice}
                scrolling="no"
                onLoad={(event) => {
                  const frame = event.currentTarget;
                  const height = frame.contentDocument?.documentElement.scrollHeight;
                  if (height) frame.style.height = `${height + 24}px`;
                }}
                srcDoc={getRenderedHtml()}
                className="w-full min-h-[900px] border-none bg-zinc-950"
                sandbox="allow-same-origin"
              />
            </div>
          </div>
        </div>
      )}

      {/* Send Test Email Modal */}
      {showTestModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 border border-zinc-800 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setShowTestModal(false)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200"
            >
              <X className="w-5 h-5" />
            </button>

            <h2 className="text-base font-bold text-zinc-100 mb-1 flex items-center gap-2">
              <Send className="w-4 h-4 text-zinc-300" />
              Send Test Notification
            </h2>
            <p className="text-xs text-zinc-400 mb-4">
              Sends an email with the customized HTML template to verify rendering across client mailboxes.
            </p>

            {testResult && (
              <div
                className={`p-3 rounded-xl text-xs mb-3 flex items-center gap-2 ${
                  testResult.success
                    ? 'bg-zinc-950 border border-emerald-800 text-emerald-300'
                    : 'bg-zinc-950 border border-zinc-700 text-zinc-300'
                }`}
              >
                {testResult.success ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <AlertCircle className="w-4 h-4 text-zinc-400 shrink-0" />
                )}
                <span>{testResult.message}</span>
              </div>
            )}

            <form onSubmit={handleSendTest} className="space-y-4 text-xs">
              <div>
                <label className="block text-zinc-400 mb-1 font-mono">Destination Email Address *</label>
                <input
                  type="email"
                  required
                  value={testEmail}
                  onChange={(e) => setTestEmail(e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 font-mono focus:border-zinc-600 focus:outline-none"
                />
              </div>

              {/* Findings are always dispatched: there is no review queue for a
                  test message, so the former "Force into review" option is gone. */}

              <div className="flex justify-end space-x-2 pt-3 border-t border-zinc-800">
                <button
                  type="button"
                  onClick={() => setShowTestModal(false)}
                  disabled={sendingTest}
                  className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 text-zinc-900 font-semibold"
                >
                  Send Test
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Reset Confirmation Modal */}
      {showResetConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 border border-zinc-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 mb-2">Apply professional default?</h3>
            <p className="text-xs text-zinc-400 leading-relaxed mb-6">
              Replace the preview with the professional navy-and-white preset. Save the template to apply it
              to future notifications.
            </p>
            <div className="flex justify-end space-x-2">
              <button
                type="button"
                onClick={() => setShowResetConfirm(false)}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmReset}
                className="px-3 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold"
              >
                Apply to preview
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Save Template Confirmation Modal */}
      {confirmSave && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 border border-zinc-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 mb-2">Save & Apply to Notifications?</h3>
            <p className="text-xs text-zinc-400 leading-relaxed mb-6">
              Persist the customized advisory template to the server so it applies to future notifications.
            </p>
            <div className="flex justify-end space-x-2">
              <button
                type="button"
                onClick={() => setConfirmSave(false)}
                disabled={savingTemplate}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmSaveAction}
                disabled={savingTemplate}
                className="px-3 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-white text-xs font-semibold"
              >
                {savingTemplate ? 'Saving…' : 'Save & Apply'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Send Test Email Confirmation Modal */}
      {confirmSendTest && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 border border-zinc-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 mb-2">Send Test Email?</h3>
            <p className="text-xs text-zinc-400 leading-relaxed mb-6">
              Sends a real email to {testEmail || '(no address entered)'} using the customized template.
              Confirm to send.
            </p>
            <div className="flex justify-end space-x-2">
              <button
                type="button"
                onClick={() => setConfirmSendTest(false)}
                disabled={sendingTest}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmSendTestAction}
                disabled={sendingTest}
                className="px-3 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-white text-xs font-semibold"
              >
                {sendingTest ? 'Sending…' : 'Send Test Email'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
