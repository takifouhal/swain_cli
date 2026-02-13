import sys

from swain_cli.subprocess_runner import run_subprocess


def test_run_subprocess_stream_false_does_not_write_stdout(capfd):
    rc, output = run_subprocess([sys.executable, "-c", "print('hello')"], stream=False)
    captured = capfd.readouterr()

    assert rc == 0
    assert output == "hello\n"
    assert captured.out == ""


def test_run_subprocess_stream_true_writes_stdout(capfd):
    rc, output = run_subprocess([sys.executable, "-c", "print('hello')"], stream=True)
    captured = capfd.readouterr()

    assert rc == 0
    assert output == "hello\n"
    assert captured.out == "hello\n"


def test_run_subprocess_truncates_captured_output(capfd):
    full = "0123456789" * 10
    rc, output = run_subprocess(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write(%r); sys.stdout.flush()" % (full,),
        ],
        stream=False,
        max_capture_chars=20,
    )
    captured = capfd.readouterr()

    assert rc == 0
    assert captured.out == ""
    assert output == full[-20:]
