const fs = require('fs');

function replaceInFile(filePath, replacements) {
  let content = fs.readFileSync(filePath, 'utf8');
  for (const [target, replacement] of replacements) {
    if (!content.includes(target)) {
      console.error(`Target not found in ${filePath}:`, target.substring(0, 80));
      process.exit(1);
    }
    content = content.replace(target, replacement);
  }
  fs.writeFileSync(filePath, content, 'utf8');
  console.log(`Successfully updated ${filePath}`);
}

// 1. Update RecipientsView.tsx
const recipientsPath = 'src/components/RecipientsView.tsx';
replaceInFile(recipientsPath, [
  [
    '<tbody className="divide-y divide-zinc-800/60">',
    '<tbody className="divide-y divide-zinc-800/60 dark:divide-zinc-800/60 light:divide-zinc-200">'
  ],
  [
    'text-center text-zinc-500">',
    'text-center text-zinc-500 dark:text-zinc-500 light:text-zinc-400">'
  ],
  [
    '<tr key={w.id} className="hover:bg-zinc-800/30 transition">',
    '<tr key={w.id} className="hover:bg-zinc-800/30 dark:hover:bg-zinc-800/30 light:hover:bg-zinc-100/60 transition">'
  ],
  [
    '<td className="py-3 px-4 font-semibold text-zinc-100 flex items-center space-x-2">',
    '<td className="py-3 px-4 font-semibold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 flex items-center space-x-2">'
  ],
  [
    '<Webhook className="w-3.5 h-3.5 text-zinc-400" />',
    '<Webhook className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-400 light:text-zinc-600" />'
  ],
  [
    '<span className="font-mono text-[11px] bg-zinc-950 px-2 py-0.5 rounded border border-zinc-800 text-zinc-300">',
    '<span className="font-mono text-[11px] bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 px-2 py-0.5 rounded border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-800">'
  ],
  [
    '<td className="py-3 px-4 font-mono text-zinc-400 max-w-xs truncate" title={w.url}>',
    '<td className="py-3 px-4 font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600 max-w-xs truncate" title={w.url}>'
  ],
  [
    '<td className="py-3 px-4 text-zinc-400">',
    '<td className="py-3 px-4 text-zinc-400 dark:text-zinc-400 light:text-zinc-600">'
  ],
  [
    '<td className="py-3 px-4 font-mono text-zinc-300">',
    '<td className="py-3 px-4 font-mono text-zinc-300 dark:text-zinc-300 light:text-zinc-800">'
  ],
  [
    `className={\`px-2 py-0.5 rounded-full text-[10px] font-mono border transition \${
                              w.active
                                ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                                : 'bg-zinc-900 text-zinc-500 border-zinc-800'
                            }\`}`,
    `className={\`px-2 py-0.5 rounded-full text-[10px] font-mono border transition \${
                              w.active
                                ? 'bg-emerald-950/60 dark:bg-emerald-950/60 light:bg-emerald-50 text-emerald-400 dark:text-emerald-400 light:text-emerald-700 border-emerald-800/60 dark:border-emerald-800/60 light:border-emerald-300'
                                : 'bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-200 text-zinc-500 dark:text-zinc-500 light:text-zinc-700 border-zinc-800 dark:border-zinc-800 light:border-zinc-300'
                            }\`}`
  ],
  [
    'className="px-2.5 py-1 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium flex items-center space-x-1 transition"',
    'className="px-2.5 py-1 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 text-xs font-medium flex items-center space-x-1 transition"'
  ],
  // Modals in RecipientsView
  [
    '<div className="bg-zinc-900 border border-zinc-800 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">',
    '<div className="bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">'
  ],
  [
    '<h2 className="text-sm font-bold text-zinc-100">Webhook Delivery Verified</h2>',
    '<h2 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900">Webhook Delivery Verified</h2>'
  ],
  [
    '<p className="text-xs text-zinc-400 mb-4">',
    '<p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-4">'
  ],
  [
    '<div className="bg-zinc-950 border border-zinc-800 rounded-xl p-3 font-mono text-[11px] space-y-2 text-zinc-300">',
    '<div className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-xl p-3 font-mono text-[11px] space-y-2 text-zinc-300 dark:text-zinc-300 light:text-zinc-800">'
  ],
  [
    '<span className="text-zinc-400 text-[10px] break-all bg-zinc-900 p-1.5 rounded block">',
    '<span className="text-zinc-400 dark:text-zinc-400 light:text-zinc-600 text-[10px] break-all bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-100 p-1.5 rounded block">'
  ],
  [
    '<h2 className="text-base font-bold text-zinc-100 mb-1 flex items-center gap-2">',
    '<h2 className="text-base font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-1 flex items-center gap-2">'
  ],
  [
    '<div className="mb-3 p-2.5 bg-zinc-950 border border-rose-800/60 rounded-xl text-xs text-rose-300 flex items-center space-x-1.5">',
    '<div className="mb-3 p-2.5 bg-zinc-950 dark:bg-zinc-950 light:bg-rose-50 border border-rose-800/60 dark:border-rose-800/60 light:border-rose-200 rounded-xl text-xs text-rose-300 dark:text-rose-300 light:text-rose-700 flex items-center space-x-1.5">'
  ],
  [
    'className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 focus:border-zinc-600 focus:outline-none"',
    'className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 light:focus:border-zinc-400 focus:outline-none"'
  ],
  [
    'className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 font-mono text-[11px] focus:border-zinc-600 focus:outline-none"',
    'className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono text-[11px] focus:border-zinc-600 light:focus:border-zinc-400 focus:outline-none"'
  ],
  [
    'className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 font-mono focus:border-zinc-600 focus:outline-none"',
    'className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 light:focus:border-zinc-400 focus:outline-none"'
  ],
  [
    '<div className="bg-zinc-900 border border-zinc-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl">',
    '<div className="bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl">'
  ]
]);
