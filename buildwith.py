import requests
import builtwith
from bs4 import BeautifulSoup
import re

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

def analyze_website(url, timeout=10):
    try:
        response = requests.get(url, timeout=timeout)
        html_content = response.text

        # Detect programming languages
        programming_languages = detect_programming_language(html_content)

        # Use builtwith library to get website details
        technologies = builtwith.builtwith(url)

        # Parse HTML to extract JavaScript libraries
        javascript_libraries = extract_javascript_libraries(html_content)

        # Get web server information from response headers
        web_server = response.headers.get("Server", "Unknown")

        return programming_languages, technologies, javascript_libraries, web_server
    except requests.Timeout:
        return None, None, None, None, "Request timed out"
    except Exception as e:
        return None, None, None, None, str(e)


# Rest of the code remains unchanged


def detect_programming_language(content):
    # Define patterns for various programming languages
    patterns = {
        "PHP": r"<\?php|\.php",
        "Python": r"python",
        "Ruby": r"ruby",
        "Java": r"\bjava\b",
        "JavaScript": r"javascript",
        "ASP.NET": r"asp\.net",
    }

    detected_languages = []

    for language, pattern in patterns.items():
        if re.search(pattern, content, re.IGNORECASE):
            detected_languages.append(language)

    return detected_languages


def extract_javascript_libraries(content):
    soup = BeautifulSoup(content, "html.parser")
    script_tags = soup.find_all("script")

    libraries = set()

    for script in script_tags:
        src = script.get("src")
        if src:
            match = re.search(r"/(.*?)(?:\.min)?\.js$", src)
            if match:
                libraries.add(match.group(1))

    return list(libraries)


if __name__ == "__main__":
    website_url = input("Enter the website URL: ")
    programming_languages, technologies, javascript_libraries, web_server = analyze_website(website_url)

    if programming_languages:
        print("Detected programming languages:", ", ".join(programming_languages))
    else:
        print("No programming language detected or an error occurred.")

    if technologies:
        print("\nWebsite technologies:")
        for tech, details in technologies.items():
            print(f"{tech}: {details}")
    else:
        print("An error occurred while fetching technologies.")

    if javascript_libraries:
        print("\nJavaScript libraries:")
        for library in javascript_libraries:
            print("- " + library)
    else:
        print("No JavaScript libraries detected.")

    print("\nWeb server:", web_server)
