# Changelog

## [1.5.0](https://github.com/arm/metis/compare/metis-v1.4.0...metis-v1.5.0) (2026-07-02)


### Features

* **cli:** Add dir_review CLI Command ([#249](https://github.com/arm/metis/issues/249)) ([df85deb](https://github.com/arm/metis/commit/df85deb9e1e35dc5bbf90235549f82add1e137c6))
* **cli:** make index-backed retrieval opt-in ([#220](https://github.com/arm/metis/issues/220)) ([b095e88](https://github.com/arm/metis/commit/b095e88be2b998937aaf02bb693a1b7675fe89a6))
* **config:** add custom config file CLI option ([#246](https://github.com/arm/metis/issues/246)) ([224fb44](https://github.com/arm/metis/commit/224fb44ef525d8d5172bcc173962cbd53e03be05))
* **csharp:** add C#/.NET support ([#245](https://github.com/arm/metis/issues/245)) ([c12b086](https://github.com/arm/metis/commit/c12b0869c3f6d6ed2defefbfd44a7db52bfd8a7c))
* **devcontainer:** Add Devcontainer Support ([#248](https://github.com/arm/metis/issues/248)) ([6ec3235](https://github.com/arm/metis/commit/6ec323568cfc2f856c81eb57fb1fcb77ee3cd3e7))
* **engine:** CodeAnchor/SourceMap for deterministic line attribution ([#230](https://github.com/arm/metis/issues/230)) ([469990c](https://github.com/arm/metis/commit/469990c79844be869805095428aaa38d3cc599b5))
* **java:** Add Java/Kotlin support ([#241](https://github.com/arm/metis/issues/241)) ([a97d856](https://github.com/arm/metis/commit/a97d85613bd102ae9acbb4960ff3735e1b7c72d0))
* **memory:** Add memory backend ([#260](https://github.com/arm/metis/issues/260)) ([c4e3cce](https://github.com/arm/metis/commit/c4e3cce1abd4d8eaf5e5aa864b49397e4aefbde0))
* **pgvector:** support pgvector halfvec indexes ([#258](https://github.com/arm/metis/issues/258)) ([2437b51](https://github.com/arm/metis/commit/2437b51b22990be6fe44e316e2943d7ee9f2a143))
* **providers:** add Anthropic, Gemini, Bedrock, Bedrock Mantle; decouple embedding provider ([#234](https://github.com/arm/metis/issues/234)) ([e0527b6](https://github.com/arm/metis/commit/e0527b65ecf0ea55f090d46f8ed472da527d2106))
* **providers:** configurable LLM retries ([#239](https://github.com/arm/metis/issues/239)) ([dfa1578](https://github.com/arm/metis/commit/dfa15788100aabe4d09ba080f8337e24ba1fb5d4))
* **rag:** use LangChain answer retrievers ([476bd8f](https://github.com/arm/metis/commit/476bd8f363d2c7bfac6d2e35517888542f0b2399))
* **rag:** use LangChain retrievers for indexed answers ([#226](https://github.com/arm/metis/issues/226)) ([476bd8f](https://github.com/arm/metis/commit/476bd8f363d2c7bfac6d2e35517888542f0b2399))
* **reachability:** Add tree-sitter C/C++ reachability review ([#199](https://github.com/arm/metis/issues/199)) ([2cfaa4c](https://github.com/arm/metis/commit/2cfaa4cf1f8a4007b869581c00f64dd6cb700fe4))
* **tools:** add engine tool selection ([#223](https://github.com/arm/metis/issues/223)) ([b3ce47d](https://github.com/arm/metis/commit/b3ce47d36318ecac5292bdf6a3e4d95c008565a9))
* **tools:** Expose index as a configurable model tool ([#236](https://github.com/arm/metis/issues/236)) ([8d4d7ef](https://github.com/arm/metis/commit/8d4d7ef3e2b9e2e8077cb82dedcb25303b9ffb1d))


### Bug Fixes

* **providers:** provider-aware token counting ([#255](https://github.com/arm/metis/issues/255)) ([9d7926a](https://github.com/arm/metis/commit/9d7926a7685bdb85acdd7169a81ec3e61497d0e4))


### Documentation

* add AArch64 Assembly to supported languages ([#254](https://github.com/arm/metis/issues/254)) ([d08ea10](https://github.com/arm/metis/commit/d08ea106beec07325388da0a17211446f953d1f9))

## [1.4.0](https://github.com/arm/metis/compare/metis-v1.3.0...metis-v1.4.0) (2026-06-03)


### Features

* **cli:** add --ignore-index support ([#182](https://github.com/arm/metis/issues/182)) ([879b344](https://github.com/arm/metis/commit/879b344fc4967baf3c694b506feb2800bf0385ca))
* **plugins:** add AArch64 assembly support ([#204](https://github.com/arm/metis/issues/204)) ([b455b72](https://github.com/arm/metis/commit/b455b720dd4fccd11be439484724e5b4d5293359))
* **plugins:** Support plugin-owned wildcard source suffixes ([#195](https://github.com/arm/metis/issues/195)) ([be0a882](https://github.com/arm/metis/commit/be0a8828fe6be7f094f78449f04afda8aa3d3677))
* **refactor:** decouple engine workflows and centralize tool policies ([#180](https://github.com/arm/metis/issues/180)) ([3c7a3bf](https://github.com/arm/metis/commit/3c7a3bf9c0c1c69ade73716c22f26de519f0233f))
* **usage:** Add token usage tracking ([#179](https://github.com/arm/metis/issues/179)) ([11eea95](https://github.com/arm/metis/commit/11eea95d1db96d76d19dc8b391cfdeac65954a1d))
* **verilog:** Add Verilog support ([#168](https://github.com/arm/metis/issues/168)) ([a457783](https://github.com/arm/metis/commit/a45778318a6b8870b87ee5efb229116a5549a53d))


### Bug Fixes

* **chroma:** serialize local store and query engine initialization ([#171](https://github.com/arm/metis/issues/171)) ([a74d5cf](https://github.com/arm/metis/commit/a74d5cf68ffb8dba48a60ee9e394cf41e0e25e2e))
* **config:** Fix CLI version handling and validate provider configuration ([#200](https://github.com/arm/metis/issues/200)) ([15d09f0](https://github.com/arm/metis/commit/15d09f05d14b9d99ef9643e7f6159f3b15293eb0))
* **config:** Support metis.yml config fallback ([#183](https://github.com/arm/metis/issues/183)) ([9af12b3](https://github.com/arm/metis/commit/9af12b32981153e13c7fe3e06bf3ba0ddb70eb43))
* **config:** support OpenAI custom base URL ([#210](https://github.com/arm/metis/issues/210)) ([2f3d5f0](https://github.com/arm/metis/commit/2f3d5f0983ec6d1ef19f421cfc7906c8db6bb3f9))
* **index:** Exclude broken symlinks while indexing ([#196](https://github.com/arm/metis/issues/196)) ([c2a0934](https://github.com/arm/metis/commit/c2a0934f947a1e040994e88b7f1696b5a9a97974))
* **metisignore:** support allowlist patterns consistently ([#181](https://github.com/arm/metis/issues/181)) ([cc42aba](https://github.com/arm/metis/commit/cc42abaf995f9a4eb5aef5a9d3e237310e73764e))
* **providers:** use Responses API for OpenAI model paths ([#206](https://github.com/arm/metis/issues/206)) ([8726024](https://github.com/arm/metis/commit/872602497fb81cf10a826c3186f0e06e6918820b))
* **review:** skip patch summaries when review_patch finds no issues ([#187](https://github.com/arm/metis/issues/187)) ([a771dc6](https://github.com/arm/metis/commit/a771dc62c746e98187c6411e9f5da5e956841d0e))
* **tree-sitter:** Fix parser compatibility in triage and indexing ([#201](https://github.com/arm/metis/issues/201)) ([3747cc2](https://github.com/arm/metis/commit/3747cc2d5d5c3bb284c1d121f3215e63d8910c9a))
* **triage:** avoid cross-thread drops of tree-sitter native nodes ([#208](https://github.com/arm/metis/issues/208)) ([d12208a](https://github.com/arm/metis/commit/d12208ae1556c24f3a7a89581b1255ff716109be))
* **triage:** Prevent triage grep drift across environments ([#186](https://github.com/arm/metis/issues/186)) ([7ec8023](https://github.com/arm/metis/commit/7ec80230b879423e6a6b36a67a043c9185da1a6a))


### Documentation

* improve adding-new-provider.md ([#216](https://github.com/arm/metis/issues/216)) ([ffb00ba](https://github.com/arm/metis/commit/ffb00ba8bf81aa9b5f978b34f02c619dabea6411))
* ollama: recommend llama3.1:8b chat model ([#212](https://github.com/arm/metis/issues/212)) ([613c898](https://github.com/arm/metis/commit/613c898859cb6795a0d43514d10ccab5e2841994))
* ollama: recommend nomic-embed-text:v1.5 embedding model ([#211](https://github.com/arm/metis/issues/211)) ([759b61d](https://github.com/arm/metis/commit/759b61d77ebb486a79c203deffb00bffde3a5c7f))

## [1.3.0](https://github.com/arm/metis/compare/metis-v1.2.0...metis-v1.3.0) (2026-03-09)


### Features

* Add Dockerfile ([#135](https://github.com/arm/metis/issues/135)) ([844c272](https://github.com/arm/metis/commit/844c272f29141b3e7fbd94f2ef8a34e072a284be))
* php, javascript plugins ([#126](https://github.com/arm/metis/issues/126)) ([fba160d](https://github.com/arm/metis/commit/fba160dde31732a408cf47f6b46d98b1629a61b1))
* **sarif:** update SARIF to store resoning ([#133](https://github.com/arm/metis/issues/133)) ([71c25da](https://github.com/arm/metis/commit/71c25da9bce3ad41c8ab041b7cc0faf5cabb7290))
* Set review_code include/exclude paths in config file ([#130](https://github.com/arm/metis/issues/130)) ([4f2e701](https://github.com/arm/metis/commit/4f2e70178d00bd2b9358e5efd2c98e7bbfc243a5))
* **triage:** Add triage analyzers and refactor plugin capability wiring ([#165](https://github.com/arm/metis/issues/165)) ([2e0bc91](https://github.com/arm/metis/commit/2e0bc91311d3c8b5ca960bc129745a82405dcceb))
* **triage:** Add triage CLI integration, docs, and tests ([#166](https://github.com/arm/metis/issues/166)) ([e01c195](https://github.com/arm/metis/commit/e01c195b72ee7196b2d4be4957ab826467023233))
* **triage:** Add triage engine, graph pipeline, and SARIF core ([#164](https://github.com/arm/metis/issues/164)) ([2e90b5e](https://github.com/arm/metis/commit/2e90b5edeaee03ad6dec9dc4a68c1f98cac7ba42))
* **vec-store:** Harden vector-store lifecycle and query-engine reuse ([a938b1b](https://github.com/arm/metis/commit/a938b1bf92205bf3e4f2d9971116681a1f4ec685))


### Bug Fixes

* **docs:** recommend llama3.1 ([#117](https://github.com/arm/metis/issues/117)) ([2bf263d](https://github.com/arm/metis/commit/2bf263d75c2d931c0ae1e18912d034ee9b4d1862))
* **docs:** Typo in metis yaml extension ([#132](https://github.com/arm/metis/issues/132)) ([58a5400](https://github.com/arm/metis/commit/58a5400cfdc146f0617f4335da493413eaa21df6))
* extract JSON object/array from mixed LLM responses ([#138](https://github.com/arm/metis/issues/138)) ([#139](https://github.com/arm/metis/issues/139)) ([ef68de6](https://github.com/arm/metis/commit/ef68de6f637e4081079183144a49f306a0b2d848))
* **metisignore:** Use .metisignore in review_patch command ([#152](https://github.com/arm/metis/issues/152)) ([f89d7fe](https://github.com/arm/metis/commit/f89d7fe426399552cdb353b83f34486f1ed4aa7f))
* **plugin:** add validations to llm security prompt ([#110](https://github.com/arm/metis/issues/110)) ([6fde583](https://github.com/arm/metis/commit/6fde583e09d1242efae6dc790969f63e689afb99))
* **sarif:** Correctly assign fields ([c8d656a](https://github.com/arm/metis/commit/c8d656a4da5ce80a700b9336444eb40b3a9b4730))
* **sarif:** Correctly assign fields ([aafec68](https://github.com/arm/metis/commit/aafec682a7cd479d683f2693872cc5f74514be62))
* save output to file in ask ([#131](https://github.com/arm/metis/issues/131)) ([5c4a713](https://github.com/arm/metis/commit/5c4a713ca816f48380e58b4d9fc3999a52f4bedd))

## [1.2.0](https://github.com/arm/metis/compare/metis-v1.1.0...metis-v1.2.0) (2025-12-02)


### Features

* **main:** add metisignore option ([#105](https://github.com/arm/metis/issues/105)) ([2465b2a](https://github.com/arm/metis/commit/2465b2a072d1e63b86b164724a838719c16a6e9e))


### Bug Fixes

* **ollama:** add default api_key for ollama langchain ([#100](https://github.com/arm/metis/issues/100)) ([c16ecc2](https://github.com/arm/metis/commit/c16ecc20daf26aa22700ccec6b013c89655cf84f))


### Documentation

* **README:** Adds a table of supported languages ([#98](https://github.com/arm/metis/issues/98)) ([3c13bae](https://github.com/arm/metis/commit/3c13bae414895e38aa494045673b22ccee6cfaaf))

## [1.1.0](https://github.com/arm/metis/compare/metis-v1.0.0...metis-v1.1.0) (2025-11-27)


### Features

* **main:** add go plugin ([#96](https://github.com/arm/metis/issues/96)) ([6f037db](https://github.com/arm/metis/commit/6f037db42c93740edb4112eb77d1f141a6650d8e))

## [1.0.0](https://github.com/arm/metis/compare/metis-v0.8.1...metis-v1.0.0) (2025-11-20)


### ⚠ BREAKING CHANGES

* local models with vLLM and Ollama support ([#89](https://github.com/arm/metis/issues/89))

### Features

* local models with vLLM and Ollama support ([#89](https://github.com/arm/metis/issues/89)) ([aaea0c8](https://github.com/arm/metis/commit/aaea0c87e45fb4b9d32229eeded4c1c19b43df74))

## [0.8.1](https://github.com/arm/metis/compare/metis-v0.8.0...metis-v0.8.1) (2025-11-18)


### Bug Fixes

* **vector:** Fix vector backend not properly propagating llm provider ([#81](https://github.com/arm/metis/issues/81)) ([91852d3](https://github.com/arm/metis/commit/91852d3d7a092a18f992b01794bdedebe6c5944b))

## [0.8.0](https://github.com/arm/metis/compare/metis-v0.7.0...metis-v0.8.0) (2025-11-18)


### Features

* **plugins:** add Solidity support (.sol) ([#82](https://github.com/arm/metis/issues/82)) ([b649919](https://github.com/arm/metis/commit/b649919ca347b2fc9b32f2d555412c61c7d16b51))

## [0.7.0](https://github.com/arm/metis/compare/metis-v0.6.0...metis-v0.7.0) (2025-11-05)


### Features

* **graph:** Use structured output ([3c4d06a](https://github.com/arm/metis/commit/3c4d06a3e463118ed61651c5e6e2061e5af1c760))
* **graph:** Use sturctured output ([e9fa60b](https://github.com/arm/metis/commit/e9fa60bb9c46ec834ec5dacc74a8395623154166))

## [0.6.0](https://github.com/arm/metis/compare/metis-v0.5.1...metis-v0.6.0) (2025-10-28)


### Features

* **graph:** introduce LangGraph ([#73](https://github.com/arm/metis/issues/73)) ([78a144f](https://github.com/arm/metis/commit/78a144f35ac1fd09b37ee632ff55bd9a7f798358))

## [0.5.1](https://github.com/arm/metis/compare/metis-v0.5.0...metis-v0.5.1) (2025-10-24)


### Bug Fixes

* **ci:** configure release-please for tag-only GitHub releases ([17a4e4e](https://github.com/arm/metis/commit/17a4e4e85ffcc682d35cb808f7caf3101cfb6a11))
* **ci:** configure release-please for tag-only GitHub releases ([2122bce](https://github.com/arm/metis/commit/2122bce4cab6ca7fedc4b2d7c344bda46de94c0a))
* **ci:** Use googleapis action and fix manifest issue ([#67](https://github.com/arm/metis/issues/67)) ([ca8cc72](https://github.com/arm/metis/commit/ca8cc72fe926aad45a32b88b8884b1f95da6f591))
* **ci:** Use token for actions ([#68](https://github.com/arm/metis/issues/68)) ([bc32431](https://github.com/arm/metis/commit/bc32431b43238c385766c8ab0d4ddcc2ab895f61))
