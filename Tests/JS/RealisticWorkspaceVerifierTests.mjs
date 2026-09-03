import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyRealisticWorkspace } from "../../scripts/verify-realistic-workspace.mjs";

async function fixture(overrides = {}) {
  const root = await mkdtemp(join(tmpdir(), "fulmar-realistic-verifier-"));
  const files = {
    "index.html": '<!doctype html><canvas id="game"></canvas><link rel="stylesheet" href="styles.css"><script src="game.js"></script>',
    "styles.css": "body{margin:0} canvas{width:100%;max-width:32rem} @media(max-width:600px){canvas{width:90vw}}",
    "game.js": `const canvas=document.querySelector('canvas');
      let score=0,level=1,next='I',paused=false;
      addEventListener('keydown',()=>{});
      function restart(){ score=0; level=1; paused=false; }
      canvas.getContext('2d').fillRect(0,0,10,10);`
  };
  Object.assign(files, overrides);
  for (const [name, content] of Object.entries(files)) await writeFile(join(root, name), content);
  return root;
}

test("accepts a complete bounded offline three-file game", async () => {
  const root = await fixture();
  try {
    const result = await verifyRealisticWorkspace(root);
    assert.equal(result.entries, 3);
    assert.ok(result.totalBytes > 192);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects missing promised behavior instead of trusting the model's claim", async () => {
  const root = await fixture({ "game.js": "const canvas=document.querySelector('canvas'); canvas.getContext('2d').fillRect(0,0,10,10);" });
  try {
    await assert.rejects(verifyRealisticWorkspace(root), /Missing promised realistic feature/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects extra files and network dependencies", async () => {
  const extra = await fixture({ "notes.txt": "unexpected artifact" });
  try {
    await assert.rejects(verifyRealisticWorkspace(extra), /Unexpected realistic workspace entries/u);
  } finally {
    await rm(extra, { recursive: true, force: true });
  }

  const networked = await fixture({
    "game.js": `const canvas=document.querySelector('canvas'); let score=0,level=1,next='I',paused=false;
      addEventListener('keydown',()=>{}); function restart(){}; fetch('https://example.com/game');`
  });
  try {
    await assert.rejects(verifyRealisticWorkspace(networked), /external network dependency/u);
  } finally {
    await rm(networked, { recursive: true, force: true });
  }
});
