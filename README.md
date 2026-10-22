# lockfile-guard

[![ci](https://github.com/OTA-EITA/lockfile-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/OTA-EITA/lockfile-guard/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/OTA-EITA/lockfile-guard/badge)](https://securityscorecards.dev/viewer/?uri=github.com/OTA-EITA/lockfile-guard)

`package-lock.json` を読んで、npm のサプライチェーン攻撃につながる依存を **`npm install` が実行される前に** 見つける TypeScript 製の CLI / GitHub Action です。

`npm audit` は「既知の脆弱性（CVE）」を探します。lockfile-guard が見るのは、まだ CVE になっていない攻撃の入口です。乗っ取られたパッケージの新しい版がインストールスクリプトで認証情報を盗む、というここ数年の npm ワームの手口を、lockfile の時点で止めることを狙っています。

```text
$ lockfile-guard --offline test/fixtures/risky
test/fixtures/risky/package-lock.json:25  HIGH   LG002  from-git@1.2.3 comes from outside the allowed registries: git+ssh://git@github.com/someone/from-git.git#0123456789abcdef0123456789abcdef01234567
test/fixtures/risky/package-lock.json:30  HIGH   LG003  plain-http@1.0.0 is downloaded over plain HTTP (http://registry.npmjs.org/plain-http/-/plain-http-1.0.0.tgz)
test/fixtures/risky/package-lock.json:12  MEDIUM LG001  esbuild@0.28.2 runs an install script
test/fixtures/risky/package-lock.json:19  MEDIUM LG001  postinstall-thing@2.0.0 runs an install script
test/fixtures/risky/package-lock.json:35  MEDIUM LG004  no-integrity@3.1.0 has no integrity hash, so npm cannot detect a tampered tarball
test/fixtures/risky/package-lock.json:39  MEDIUM LG006  expresss looks like a typo of the popular package express
test/fixtures/risky/package-lock.json:44  MEDIUM LG006  cross_env looks like a typo of the popular package cross-env
test/fixtures/risky/package-lock.json:55  MEDIUM LG001  fresh-dep@1.0.1 runs an install script

1 lockfile(s), 8 finding(s): 2 high, 6 medium, 0 low
```

## チェック内容

| ID    | 重大度 | 内容                                                                                              | レジストリ |
| ----- | ------ | ------------------------------------------------------------------------------------------------- | :--------: |
| LG001 | medium | preinstall / install / postinstall スクリプトを実行するパッケージ                                 |            |
| LG002 | high   | git URL や許可していないホストから取得される tarball（レジストリの署名を経由しない）              |            |
| LG003 | high   | `http://` で取得される tarball（通信路で差し替えられる）                                          |            |
| LG004 | medium | integrity（sha512）がなく、改ざんを検出できない                                                   |            |
| LG005 | medium | 公開から日が浅い版（既定 7 日未満）。インストールスクリプトも持つ場合は high                      |     ✓      |
| LG006 | medium | 人気パッケージ名の 1 文字違い・入れ替え・区切り文字違い（`expresss`、`lodahs`、`cross_env` など） |            |
| LG007 | low    | メンテナーが非推奨（deprecated）にした版                                                          |     ✓      |

「レジストリ」に ✓ がついたルールは npm レジストリのメタデータを参照します。`--offline` ではスキップします。

## 使い方

### CLI

```sh
npx github:OTA-EITA/lockfile-guard            # カレントディレクトリ以下の lockfile をすべて検査
npx github:OTA-EITA/lockfile-guard --offline  # ネットワークに出ない検査だけ
```

| オプション              | 説明                                                                                            |
| ----------------------- | ----------------------------------------------------------------------------------------------- |
| `--min-age <日数>`      | この日数未満の版を LG005 として報告（既定 7）                                                   |
| `--registry <url>`      | 許可するレジストリ。複数指定可（既定は `$npm_config_registry` か `https://registry.npmjs.org`） |
| `--allow-scripts <pkg>` | インストールスクリプトを確認済みのパッケージ。複数指定・カンマ区切り可                          |
| `--format <形式>`       | `text` / `json` / `markdown` / `sarif`                                                          |
| `--fail-on <重大度>`    | この重大度以上の検出で終了コード 1（`high` / `medium` / `low` / `none`、既定 `medium`）         |
| `--list-rules`          | ルールの一覧を表示                                                                              |

プライベートレジストリは `NPM_TOKEN` 環境変数のトークンで参照します。

### GitHub Actions

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v5
    with:
      persist-credentials: false
  - uses: OTA-EITA/lockfile-guard@v0.1.0 # 実運用ではコミット SHA で固定してください
    id: guard
    with:
      fail-on: high
      allow-scripts: esbuild
  - uses: github/codeql-action/upload-sarif@v4
    if: always()
    with:
      sarif_file: ${{ steps.guard.outputs.sarif-file }}
      category: lockfile-guard
```

検出結果は PR のアノテーション、ジョブのサマリー（Markdown の表）、SARIF（Code scanning）に出ます。
入力は `path`・`fail-on`・`min-age`・`allow-scripts`・`offline`・`sarif-file`、出力は `sarif-file`・`findings` です（[`action.yml`](action.yml)）。

## 設計のポイント

- **`npm install` より前に動く**: lockfile を読むだけなので、依存をインストールせず、インストールスクリプトも実行せずに判定できます。CI で `npm ci` の前段に置けます
- **クールダウン（LG005）**: 乗っ取られた版の多くは数日以内に発見・削除されます。公開から一定期間たっていない版を止めれば、その期間に入り込むのを防げます。インストールスクリプトを持つ新しい版は特に危険なので high にしています
- **偽陽性を抑えたタイポスクワット判定（LG006）**: 編集距離（隣接文字の入れ替えを 1 と数える OSA 距離）が 1 のものを対象にし、4 文字以下の名前は正当な近い名前が多いため対象外。人気パッケージ自体や npm エイリアス（`"name"` フィールド）も正しく扱います
- **依存ゼロ**: 実行時の依存はなく、Node.js の標準ライブラリ（`fetch`・`util.parseArgs`）だけで動きます。ツール自体がサプライチェーンのリスクにならないようにしています
- **レジストリへの問い合わせ**: 同じパッケージは 1 回だけ、同時 8 件までに制限し、429 / 5xx はリトライ。テストではレジストリと現在時刻を差し替えて、ネットワークなしで検証しています
- **型の厳しさ**: `strict` に加えて `noUncheckedIndexedAccess` と `exactOptionalPropertyTypes` を有効にし、typescript-eslint の `strictTypeChecked` で lint

## このリポジトリ自身の守り

- CI は Node.js 24 の最新パッチ（`check-latest`）で、`npm ci --ignore-scripts`・`npm audit`・`npm audit signatures` を実行
- lockfile-guard 自身でこのリポジトリの lockfile を検査（クールダウン 7 日を含む）。開発用の依存も、公開から 7 日以上たった版だけで lockfile を作っています（`npm install --before`）
- Dependabot も `cooldown: 7 日` で、同じ方針で更新を提案
- GitHub Actions はすべてコミット SHA で固定し、[gha-guard](https://github.com/OTA-EITA/gha-guard) で検査

## 開発

```sh
npm ci --ignore-scripts
npm run coverage   # Vitest（カバレッジのしきい値つき）
npm run lint
npm run build      # dist/ を更新したらコミットする
```

## License

MIT
