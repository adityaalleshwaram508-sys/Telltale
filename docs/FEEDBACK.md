# Feedback on the tools

Notes from building Telltale on Nebius Token Factory with NVIDIA Nemotron models, written for
the Nebius x NVIDIA Global AI Hackathon feedback requirement. These are the things that
actually helped and the things that actually cost me time.

## Nebius Token Factory

Token Factory speaking the OpenAI API is the reason this project has a per-step model table at
all. The client is the OpenAI SDK with `base_url` pointed at Token Factory and nothing else
changed. Moving a step between Nemotron Nano, Super and Ultra is a one line model id change, so
routing the cheap extraction call to Nano and only the verdict to Super took minutes to try
instead of a rewrite. There were no GPUs to provision and no inference server to keep warm.

Two things cost me time.

Strict `json_schema` structured output did not behave identically across the models I tried, so
I kept a `json_object` fallback and a single repair pass rather than relying on it. That is the
right engineering decision anyway, but I arrived at it by hitting the difference rather than by
reading about it.

`chat_template_kwargs` for setting the reasoning mode per call is the most useful thing in the
whole integration for a latency sensitive app, and I found it by reading rather than by looking
it up. Nemotron 3 reasons by default, most of my steps do not need it, and turning it off per
step is what keeps the pipeline responsive. Both of these would be worth putting near the front
of the quickstart rather than leaving a builder to discover them.

One gap. There is no Nemotron vision model on Token Factory, so screenshot input goes through
MiniCPM-V 4.5. That works, but it means the one multimodal path in my app leaves the Nemotron
family.

## NVIDIA Nemotron

The Nano and Super split held up better than I expected. Nemotron 3 Nano 30B handles short
structured extraction reliably at a fraction of the cost, and I only needed Super 120B for the
one step that actually weighs evidence against a claim.

Low reasoning effort on the verdict step was the right setting. Off was too shallow and the
verdicts got sloppy. Higher was slower without changing the answer on my benchmark. Having
three discrete settings rather than a single on and off switch is what made that tunable at
all. Nemotron 3 Ultra is wired in as an optional second opinion for medium risk verdicts and
for runs where two or more of the model's own claims were rejected by my verifier.

Per call token usage and latency came back reliably, which is why every result in the app can
show which model ran at each step with its reasoning mode, its latency and its token count.
That transparency panel is a feature of my product that only exists because the API returned
the numbers without my having to estimate them.

## Nebius Serverless

I deployed the container elsewhere because I had it running before I looked at Serverless
Endpoints. Given more time I would move it, mainly to keep the inference and the application on
the same infrastructure rather than for any problem with the current setup.

## Tavily

`exact_match` and `exclude_domains` are the two features the whole evidence design rests on.

`exact_match` means a result only comes back if it names the message's own link, phone number
or UPI id. Without it, a search for a scam domain returns a pile of articles about similar
scams, and any of them can be made to look like confirmation of a specific claim. With it, a
result either names the thing or it does not come back, which is what lets me treat a returned
source as evidence rather than as atmosphere.

`exclude_domains` means the suspect domain is never cited as evidence about itself. A scam site
describing itself as the official parcel tracking portal is exactly the kind of source that
would otherwise sail through a naive relevance check.

Without those two I would have had to build result filtering myself, and I would have trusted
it considerably less. The one thing I would want next is a way to express recency intent per
query without hardcoding a date range, since scam infrastructure turns over fast and a two year
old report about a domain means something different from a two week old one.
