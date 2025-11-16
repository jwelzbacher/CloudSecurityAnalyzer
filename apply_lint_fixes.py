#!/usr/bin/env python3
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent


def replace_in_file(path: pathlib.Path, replacements: list[tuple[str, str]]) -> None:
    text = path.read_text()
    original = text
    for old, new in replacements:
        if old in text:
            text = text.replace(old, new)
        else:
            print(f"[WARN] Pattern not found in {path}: {old!r}")
    if text != original:
        path.write_text(text)
        print(f"[OK] Updated {path}")
    else:
        print(f"[INFO] No changes for {path}")


def strip_whitespace_only_lines(path: pathlib.Path) -> None:
    text = path.read_text()
    new_text = re.sub(r'^[ \t]+$', '', text, flags=re.MULTILINE)
    if new_text != text:
        path.write_text(new_text)
        print(f"[OK] Stripped whitespace-only lines in {path}")


def main() -> None:
    # 1) cs_kit/cli/main.py – B904
    main_py = ROOT / "cs_kit" / "cli" / "main.py"
    if main_py.exists():
        replace_in_file(main_py, [
            (
                '    except KeyboardInterrupt:\n'
                '        console.print("\\n[yellow]Scan interrupted by user[/yellow]")\n'
                '        raise typer.Exit(1)\n',
                '    except KeyboardInterrupt:\n'
                '        console.print("\\n[yellow]Scan interrupted by user[/yellow]")\n'
                '        raise typer.Exit(1) from None\n',
            ),
            (
                '    except Exception as e:\n'
                '        console.print(f"\\n[red]Scan failed: {e}[/red]")\n'
                '        raise typer.Exit(1)\n',
                '    except Exception as e:\n'
                '        console.print(f"\\n[red]Scan failed: {e}[/red]")\n'
                '        raise typer.Exit(1) from e\n',
            ),
            (
                '    except Exception as e:\n'
                '        console.print(f"[red]Failed to generate report: {e}[/red]")\n'
                '        raise typer.Exit(1)\n',
                '    except Exception as e:\n'
                '        console.print(f"[red]Failed to generate report: {e}[/red]")\n'
                '        raise typer.Exit(1) from e\n',
            ),
            (
                '    except Exception as e:\n'
                '        console.print(f"[red]Configuration validation failed: {e}[/red]")\n'
                '        raise typer.Exit(1)\n',
                '    except Exception as e:\n'
                '        console.print(f"[red]Configuration validation failed: {e}[/red]")\n'
                '        raise typer.Exit(1) from e\n',
            ),
        ])

    # 2) cs_kit/cli/main_click.py – B904
    main_click_py = ROOT / "cs_kit" / "cli" / "main_click.py"
    if main_click_py.exists():
        replace_in_file(main_click_py, [
            (
                '    except Exception as e:\n'
                '        console.print(f"[red]Configuration error: {e}[/red]")\n'
                '        raise click.Abort()\n',
                '    except Exception as e:\n'
                '        console.print(f"[red]Configuration error: {e}[/red]")\n'
                '        raise click.Abort() from e\n',
            ),
            (
                '    except KeyboardInterrupt:\n'
                '        console.print("\\n[yellow]Scan interrupted by user[/yellow]")\n'
                '        raise click.Abort()\n',
                '    except KeyboardInterrupt:\n'
                '        console.print("\\n[yellow]Scan interrupted by user[/yellow]")\n'
                '        raise click.Abort() from None\n',
            ),
            (
                '    except Exception as e:\n'
                '        console.print(f"\\n[red]Scan failed: {e}[/red]")\n'
                '        raise click.Abort()\n',
                '    except Exception as e:\n'
                '        console.print(f"\\n[red]Scan failed: {e}[/red]")\n'
                '        raise click.Abort() from e\n',
            ),
            (
                '    except Exception as e:\n'
                '        console.print(f"[red]Failed to generate report: {e}[/red]")\n'
                '        raise click.Abort()\n',
                '    except Exception as e:\n'
                '        console.print(f"[red]Failed to generate report: {e}[/red]")\n'
                '        raise click.Abort() from e\n',
            ),
            (
                '    except Exception as e:\n'
                '        console.print(f"[red]Configuration validation failed: {e}[/red]")\n'
                '        raise click.Abort()\n',
                '    except Exception as e:\n'
                '        console.print(f"[red]Configuration validation failed: {e}[/red]")\n'
                '        raise click.Abort() from e\n',
            ),
        ])

    # 3) cs_kit/normalizer/parser.py – B904
    parser_py = ROOT / "cs_kit" / "normalizer" / "parser.py"
    if parser_py.exists():
        replace_in_file(parser_py, [
            (
                '    except json.JSONDecodeError as e:\n'
                '        raise json.JSONDecodeError(f"Invalid JSON in {path}: {e.msg}", e.doc, e.pos)\n',
                '    except json.JSONDecodeError as e:\n'
                '        raise json.JSONDecodeError(\n'
                '            f"Invalid JSON in {path}: {e.msg}", e.doc, e.pos\n'
                '        ) from e\n',
            ),
        ])

    # 4) cs_kit/cli/main_simple.py – B905 zip strict=
    main_simple_py = ROOT / "cs_kit" / "cli" / "main_simple.py"
    if main_simple_py.exists():
        replace_in_file(main_simple_py, [
            (
                '    header_line = " | ".join(h.ljust(w) for h, w in zip(headers, widths))\n',
                '    header_line = " | ".join(h.ljust(w) for h, w in zip(headers, widths, strict=False))\n',
            ),
            (
                '        row_line = " | ".join(str(cell).ljust(w) for cell, w in zip(row, widths))\n',
                '        row_line = " | ".join(str(cell).ljust(w) for cell, w in zip(row, widths, strict=False))\n',
            ),
        ])

    # 5) cs_kit/cli/tool_registry.py – W293 blank lines
    tool_registry_py = ROOT / "cs_kit" / "cli" / "tool_registry.py"
    if tool_registry_py.exists():
        strip_whitespace_only_lines(tool_registry_py)

    # 6) cs_kit/web/app.py – W293 blank lines
    web_app_py = ROOT / "cs_kit" / "web" / "app.py"
    if web_app_py.exists():
        strip_whitespace_only_lines(web_app_py)

    # 7) cs_kit/render/pdf.py – E402, mark imports as noqa
    pdf_py = ROOT / "cs_kit" / "render" / "pdf.py"
    if pdf_py.exists():
        replace_in_file(pdf_py, [
            (
                "from cs_kit.cli.config import RendererConfig\n",
                "from cs_kit.cli.config import RendererConfig  # noqa: E402\n",
            ),
            (
                "from cs_kit.normalizer.ocsf_models import FindingSummary, OCSFEnrichedFinding\n",
                "from cs_kit.normalizer.ocsf_models import FindingSummary, OCSFEnrichedFinding  # noqa: E402\n",
            ),
            (
                "from cs_kit.normalizer.summarize import (\n",
                "from cs_kit.normalizer.summarize import (  # noqa: E402\n",
            ),
        ])

    # 8) scripts/setup_aws_dev_env.py – F401 unused BotoCoreError
    setup_env_py = ROOT / "scripts" / "setup_aws_dev_env.py"
    if setup_env_py.exists():
        replace_in_file(setup_env_py, [
            (
                "    from botocore.exceptions import BotoCoreError, ClientError\n",
                "    from botocore.exceptions import ClientError\n",
            ),
        ])

    # 9) tests/test_tool_registry.py – B007 unused provider
    test_tool_reg_py = ROOT / "tests" / "test_tool_registry.py"
    if test_tool_reg_py.exists():
        replace_in_file(test_tool_reg_py, [
            (
                "        for provider, scanners in PROVIDER_SUPPORT.items():\n",
                "        for _provider, scanners in PROVIDER_SUPPORT.items():\n",
            ),
        ])

    print("Done applying scripted lint fixes.")


if __name__ == "__main__":
    main()

