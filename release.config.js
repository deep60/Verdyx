/** @type {import('semantic-release').Options} */
module.exports = {
  branches: ['main'],
  plugins: [
    '@semantic-release/commit-analyzer',
    '@semantic-release/release-notes-generator',
    '@semantic-release/changelog',
    '@semantic-release/npm',
    '@semantic-release/github',
    '@semantic-release/git',
    [
      '@semantic-release/exec',
      {
        prepareCmd: 'echo "Preparing release ${nextRelease.version}"',
        publishCmd: 'echo "Publishing release ${nextRelease.version}"',
        successCmd: 'echo "Release ${nextRelease.version} published successfully"',
        failCmd: 'echo "Release failed"',
      },
    ],
  ],
  preset: 'conventionalcommits',
  commitAnalyzer: {
    preset: 'conventionalcommits',
    releaseRules: [
      { type: 'feat', release: 'minor' },
      { type: 'fix', release: 'patch' },
      { type: 'perf', release: 'patch' },
      { type: 'refactor', release: 'patch' },
      { type: 'docs', release: 'patch' },
      { type: 'style', release: false },
      { type: 'chore', release: false },
      { type: 'test', release: false },
      { type: 'build', release: 'patch' },
      { type: 'ci', release: false },
      { scope: 'contracts', release: 'minor' },
      { scope: 'security', release: 'patch' },
      { breaking: true, release: 'major' },
    ],
  },
  releaseNotesGenerator: {
    preset: 'conventionalcommits',
    presetConfig: {
      types: [
        { type: 'feat', section: '✨ Features' },
        { type: 'fix', section: '🐛 Bug Fixes' },
        { type: 'perf', section: '⚡ Performance Improvements' },
        { type: 'refactor', section: '♻️ Refactoring' },
        { type: 'docs', section: '📚 Documentation' },
        { type: 'security', section: '🔒 Security' },
        { type: 'build', section: '🏗️ Build System' },
        { type: 'ci', section: '🔄 CI/CD' },
      ],
    },
  },
  changelog: {
    changelogFile: 'CHANGELOG.md',
    changelogTitle: '# Changelog\n\nAll notable changes to this project will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),\nand this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).\n',
  },
  github: {
    assets: [
      { path: 'CHANGELOG.md', label: 'Changelog' },
    ],
  },
  git: {
    assets: ['CHANGELOG.md', 'package.json', 'backend/Cargo.toml'],
    message: 'chore(release): ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}',
  },
  npm: {
    pkgRoot: './frontend',
  },
};