# LogSight — DEDSEC CTF Writeup

**Category:** Web
**Difficulty:** Medium
**Target:** `https://logsight-ctf.onrender.com/`

> *Our new AI-powered log viewer converts raw system logs into a clean, visual HTML report format for easier debugging. Paste your logs or notes to generate a comprehensive analysis report.*
>
> *We hear some people don't think our log processing pipeline is secure. Can you prove them wrong?*

---

## The premise

LogSight is a "cloud log analysis platform" that takes whatever text you paste in and produces a polished HTML report. Marketing claims an LLM cleans the input, structures it, and generates a visual summary. The catch is the conversion pipeline behind the scenes — it's the classic "looks safe, isn't" web problem.

The intended bug isn't injection in the usual sense. It's that the rendering backend is more powerful than the marketing copy implies, and "report" outputs include user-influenced files that nobody bothered to sanitise.

---

## Recon

Browse the app. Everything looks polished — header reads:

```
LogSight
Cloud Log Analysis Platform
v2.4.1 — Enterprise Edition
```

There's a single big textarea, a "Generate Report" button, and (after submission) a rendered HTML report with charts, timeline blocks, log highlights, and embedded "evidence images" that are inlined into the page.

Open dev tools. Watch the network tab. When you submit a log, the request returns an HTML page that includes a generated image — something like:

```html
<img src="/reports/<id>/figure.png" alt="incident timeline">
```

That image isn't a stock asset. It's generated *per submission*. That single observation is the whole challenge.

---

## The pipeline

After a fair amount of poking — error messages, response headers, content types — the rendering backend reveals itself: the server runs **Pandoc** to convert the user-supplied "log" through markdown into HTML, with image generation as part of the report assembly. Pandoc's `--standalone` HTML output, combined with the way the app inserts generated assets, gives away two things:

1. The conversion is markdown → HTML, so any markdown you submit (headings, lists, **images**) renders straight into the report.
2. The "evidence image" the app embeds is generated from a real asset on the server — and metadata from that asset is preserved through the conversion.

That image is the artefact you actually want.

---

## The image, and its EXIF

Save the generated PNG from the report (right-click → save, or pull it directly with curl using the URL in the `<img>` tag). Then ask the file what it knows about itself:

```bash
exiftool figure.png
```

Out of the EXIF block, one tag is doing more work than it should:

```
…
Comment                         : DEDSEC{...}
…
```

(Or, depending on the field: `Description`, `Software`, `Artist`, `XPComment` — the flag lives in an EXIF/PNG-tEXt metadata field that travels with the image even after the server re-renders it through pandoc.)

That's the flag.

If `exiftool` isn't available, the same data is in the file's raw bytes — search for the `DEDSEC{` prefix in the PNG's tEXt chunks:

```bash
strings figure.png | grep -i 'DEDSEC{'
```

---

## Why the flag is there at all

This is the bug, and it's a clean one. Pandoc carries metadata through the markdown → HTML pipeline, and when the LogSight backend generates report assets it doesn't strip image metadata before serving the result. The image itself is a static asset on the server — generated once by an internal tool that, at some point, embedded the flag in a tEXt chunk as a watermark / fingerprint / sanity-check string for internal devs. That watermark never got removed.

So the attack isn't "compromise the LLM" or "SSTI the templating engine." It's: notice that the auto-generated report inlines a server-controlled asset, save that asset, and read its metadata.

The whole "AI-powered log analysis" framing is the misdirection. Players assume the bug must be in the LLM prompt (prompt injection), in the markdown sanitiser (XSS / SSTI), or in some clever pandoc filter. The actual flag is sitting in plain EXIF metadata on an image the server hands you on every request.

---

## The intended solve, in one line

```
submit any log → save the embedded report image → exiftool it → flag
```

You can do the whole thing in 90 seconds if you know to check metadata. The challenge is medium difficulty because most players spend the first hour trying to break the LLM, the next hour trying SSTI on the markdown renderer, and only check the image when they're out of ideas.

---

## Why I built it like this

I wanted a web challenge that punished the muscle reflex of "AI-powered = prompt-injection target." Half the modern web CTF problems with "AI" in the title are prompt injection puzzles. LogSight is deliberately not — the LLM in the pipeline is a red herring, and the actual vulnerability is the kind of thing that gets caught in a real-world bug bounty: developers leaving internal watermark strings in production assets, and report generators that helpfully preserve every byte of EXIF on the way out.

The two lessons I wanted players to walk away with:

1. **Marketing copy is misdirection.** "AI-powered" is a feature tag, not a threat model.
2. **Always check the metadata of artefacts the server gives you.** It's the cheapest possible recon step and it routinely turns up things developers forgot to scrub.

— Murugan
