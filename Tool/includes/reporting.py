import json

class ReportGenerator:
    def __init__(self, results):
        self.results = results

    def save_as_text(self, filename):
        with open(filename, "w") as file:
            for task, result in self.results.items():
                file.write(f"{task}:\n{result}\n\n")
        print(f"Report saved as {filename}")

    def save_as_html(self, filename):
        with open(filename, "w") as file:
            file.write("<html><body>")
            for task, result in self.results.items():
                file.write(f"<h2>{task}</h2><p>{result}</p>")
            file.write("</body></html>")
        print(f"Report saved as {filename}")

    def save_as_json(self, filename):
        with open(filename, "w") as file:
            json.dump(self.results, file, indent=4)
        print(f"Report saved as {filename}")
