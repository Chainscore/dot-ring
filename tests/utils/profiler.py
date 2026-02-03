import cProfile
import io
import pstats
import subprocess
import time
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any


class Profiler:
    """Context manager for profiling code blocks"""

    def __init__(
        self,
        name: str,
        save_stats: bool = True,
        print_stats: bool = True,
        sort_by: str = "cumulative",
        limit: int = 20,
    ):
        self.name = name
        self.save_stats = save_stats
        self.print_stats = print_stats
        self.sort_by = sort_by
        self.limit = limit
        self.profiler = None
        self.start_time = None

    def __enter__(self):
        print(f"\n🚀 Profiling: {self.name}")
        self.start_time = time.perf_counter()
        self.profiler = cProfile.Profile()
        self.profiler.enable()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.profiler.disable()
        end_time = time.perf_counter()
        total_time = end_time - self.start_time

        print(f"✅ {self.name} completed in: {total_time:.4f} seconds")

        if self.print_stats:
            self._print_stats()

        if self.save_stats:
            self._save_stats()

    def _print_stats(self):
        """Print profiling statistics to console"""
        s = io.StringIO()
        ps = pstats.Stats(self.profiler, stream=s).sort_stats(self.sort_by)
        ps.print_stats(self.limit)

        print(f"\n📊 Profiling results for {self.name} (top {self.limit}, sorted by {self.sort_by}):")
        print("=" * 80)
        print(s.getvalue())
        print("=" * 80)

    def _save_stats(self):
        """Save profiling statistics to files"""
        # Create date-organized output directory
        from datetime import datetime

        today = datetime.now().strftime("%Y-%m-%d")
        output_dir = Path("perf") / "results" / today
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate safe filename
        safe_name = "".join(c for c in self.name if c.isalnum() or c in (" ", "-", "_")).rstrip()
        safe_name = safe_name.replace(" ", "_")

        # Save binary stats file (overwrite if exists)
        stats_file = output_dir / f"{safe_name}.prof"
        self.profiler.dump_stats(str(stats_file))

        # Save human-readable text report
        text_file = output_dir / f"{safe_name}.txt"
        with open(text_file, "w") as f:
            f.write(f"Profiling Report: {self.name}\n")
            f.write(f"Date: {today}\n")
            f.write("=" * 50 + "\n\n")

            # Write stats to file using StringIO buffer
            s = io.StringIO()
            ps = pstats.Stats(self.profiler, stream=s)
            ps.sort_stats(self.sort_by)
            ps.print_stats(self.limit)
            f.write(s.getvalue())

        print(f"📄 Profile saved: {stats_file}")
        print(f"📄 Report saved: {text_file}")

        # Generate dot file
        self._generate_dot_file(stats_file, safe_name)

    def _generate_dot_file(self, stats_file: Path, name: str):
        """Generate dot file using gprof2dot"""
        output_dir = stats_file.parent
        dot_file = output_dir / f"{name}.dot"

        try:
            # Check if gprof2dot is available
            subprocess.run(["gprof2dot", "--help"], capture_output=True, check=True)

            # Generate dot file
            with open(dot_file, "w") as f:
                subprocess.run(["gprof2dot", "-f", "pstats", str(stats_file)], stdout=f, check=True)

            print(f"📊 Dot file saved: {dot_file}")

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"⚠️  gprof2dot not available: {e}")
            print("Install with: pip install gprof2dot")
            # Create a simple text-based call tree instead
            self._create_text_visualization(stats_file, name)

    def _create_text_visualization(self, stats_file: Path, name: str):
        """Create a simple text-based visualization"""
        output_dir = stats_file.parent
        viz_file = output_dir / f"{name}_calltree.txt"

        with open(viz_file, "w") as f:
            f.write(f"Call Tree for {self.name}\n")
            f.write("=" * 50 + "\n\n")

            ps = pstats.Stats(str(stats_file))
            ps.sort_stats("cumulative")
            # Redirect stdout to file temporarily
            import sys

            old_stdout = sys.stdout
            sys.stdout = f
            ps.print_callers()
            sys.stdout = old_stdout

        print(f"📊 Call tree saved: {viz_file}")


def profile(sort_by: str = "cumulative", limit: int = 20, save_stats: bool = True):
    """Decorator to profile a function"""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            with Profiler(func.__name__, save_stats=save_stats, sort_by=sort_by, limit=limit):
                return func(*args, **kwargs)

        return wrapper

    return decorator


def profile_function(
    func: Callable,
    *args,
    sort_by: str = "cumulative",
    limit: int = 20,
    save_stats: bool = True,
    **kwargs,
) -> Any:
    """Profile a function call and return its result"""
    with Profiler(func.__name__, save_stats=save_stats, sort_by=sort_by, limit=limit):
        return func(*args, **kwargs)


def compare_profiles(profile1: str, profile2: str, output_file: str | None = None):
    """Compare two profile files and show differences"""
    try:
        stats1 = pstats.Stats(profile1)
        stats2 = pstats.Stats(profile2)

        print("\n📊 Comparing profiles:")
        print(f"Profile 1: {profile1}")
        print(f"Profile 2: {profile2}")
        print("=" * 60)

        # Get top functions from each profile
        s1 = io.StringIO()
        s2 = io.StringIO()

        # Use print_stats without stream parameter
        import sys

        old_stdout = sys.stdout

        sys.stdout = s1
        stats1.sort_stats("cumulative").print_stats(10)

        sys.stdout = s2
        stats2.sort_stats("cumulative").print_stats(10)

        sys.stdout = old_stdout

        print("Top functions in Profile 1:")
        print(s1.getvalue())
        print("\nTop functions in Profile 2:")
        print(s2.getvalue())

        if output_file:
            with open(output_file, "w") as f:
                f.write("Profile Comparison\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Profile 1: {profile1}\n")
                f.write(s1.getvalue())
                f.write(f"\nProfile 2: {profile2}\n")
                f.write(s2.getvalue())
            print(f"📄 Comparison saved: {output_file}")

    except Exception as e:
        print(f"❌ Error comparing profiles: {e}")


def view_profile(profile_file: str, sort_by: str = "cumulative", limit: int = 20):
    """View a saved profile file"""
    try:
        stats = pstats.Stats(profile_file)
        stats.sort_stats(sort_by)
        stats.print_stats(limit)
    except Exception as e:
        print(f"❌ Error viewing profile: {e}")


def list_profiles(directory: str = "perf/results") -> list[str]:
    """List all available profile files (legacy function)"""
    try:
        from datetime import datetime

        # Default to today's directory if using old default
        if directory == "perf/results":
            today = datetime.now().strftime("%Y-%m-%d")
            directory = f"perf/results/{today}"

        profile_dir = Path(directory)
        if not profile_dir.exists():
            print(f"📁 No profile directory found: {directory}")
            return []

        profiles = list(profile_dir.glob("*.prof"))
        if not profiles:
            print(f"📁 No profile files found in: {directory}")
            return []

        print(f"📊 Available profiles in {directory}:")
        for i, profile in enumerate(profiles, 1):
            print(f"  {i}. {profile.name}")

        return [str(p) for p in profiles]

    except Exception as e:
        print(f"❌ Error listing profiles: {e}")
        return []


# Convenience functions for quick profiling
def quick_profile(func: Callable, *args, **kwargs) -> Any:
    """Quick profile without saving files"""
    with Profiler(func.__name__, save_stats=False, limit=10):
        return func(*args, **kwargs)


def time_and_profile(func: Callable, *args, **kwargs) -> tuple:
    """Time and profile a function, return (result, execution_time)"""
    start_time = time.perf_counter()
    with Profiler(func.__name__, print_stats=False, save_stats=True):
        result = func(*args, **kwargs)
    end_time = time.perf_counter()

    execution_time = end_time - start_time
    print(f"⏱️  Total execution time: {execution_time:.4f} seconds")

    return result, execution_time
