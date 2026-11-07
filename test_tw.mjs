import { compile } from '@tailwindcss/node';

async function test() {
  const css = `@import "tailwindcss";
@custom-variant dark (&:is(.dark, .dark *));
@custom-variant light (&:is(.light, .light *));
`;
  const compiled = await compile(css, {
    base: process.cwd(),
    onDependency: () => {}
  });

  const sampleClasses = [
    'bg-zinc-900',
    'dark:bg-zinc-900',
    'light:bg-white',
    'text-zinc-100',
    'dark:text-zinc-100',
    'light:text-zinc-900',
    'border-zinc-800',
    'light:border-zinc-200',
    'hover:bg-zinc-800',
    'light:hover:bg-zinc-100'
  ];

  const res = compiled.build(sampleClasses);
  console.log(res.substring(res.lastIndexOf('@layer utilities')));
}

test().catch(console.error);
