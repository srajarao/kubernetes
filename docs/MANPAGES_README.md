# Man Pages Documentation

This directory contains Unix manual pages (man pages) converted from various project documentation files.

## Available Man Pages

### System Administration (Section 8)
- `migration-checklist.8` - K3s cluster network migration guide
- `project-plan.8` - K3s multi-node AI cluster production deployment system
- `migration-timeline.8` - Network migration timeline from 10.1.10.x to 192.168.1.x
- `script-executor-project-plan.8` - Script execution web interface project plan
- `pod-deployment-architecture.8` - Script executor K3s pod deployment architecture
- `multi-select-tree-design.8` - Multi-select tree interface design for script executor
- `cluster-tree-design.8` - Tree view design concept for cluster script management
- `bootstrap-solution.8` - Bootstrap problem solution for script executor deployment

## Usage

To view any man page, use:

```bash
man docs/<manpage>.8
```

For example:
```bash
man docs/project-plan.8
```

## Conversion Details

All man pages were converted from Markdown format to troff/nroff format using standard man page macros:
- `.TH` - Title header
- `.SH` - Section headers
- `.SS` - Subsection headers
- `.TP` - Tagged paragraphs
- `.nf/.fi` - No-fill regions for code blocks
- `.IP` - Indented paragraphs
- `.BR` - Bold/regular text
- `.RS/.RE` - Relative indent start/end

## Original Files

The original Markdown files have been archived in the `archive/` directory for historical reference.

## Sections

- **Section 8**: System administration commands and procedures
- All pages include NAME, SYNOPSIS, DESCRIPTION sections
- Cross-references to related documentation
- Author and history information


