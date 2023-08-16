import requests
from urllib.parse import urlparse, urljoin

# Define the URL of the website you want to check
website_url = "https://spyboy.blog"  # Replace with your desired URL

# Set timeout values in seconds
timeout = 10

# Check for robots.txt
robots_url = urljoin(website_url, "/robots.txt")
robots_response = requests.get(robots_url, timeout=timeout)

if robots_response.status_code == 200:
    print("Robots.txt file exists.")
    print("Robots.txt URL:", robots_url)
    robots_content = robots_response.text
    print("Robots.txt content:")
    print(robots_content)

    # Find sitemap directive in robots.txt
    sitemap_directive = None
    for line in robots_content.split('\n'):
        if line.lower().startswith("sitemap:"):
            sitemap_directive = line.split(':', 1)[1].strip()
            break

    if sitemap_directive:
        sitemap_url = urljoin(website_url, sitemap_directive)
        sitemap_response = requests.get(sitemap_url, timeout=timeout)

        if sitemap_response.status_code == 200:
            print("\nSitemap URL:", sitemap_url)
            print("Sitemap content:")
            print(sitemap_response.text)
        else:
            print("\nFailed to fetch sitemap. Status code:", sitemap_response.status_code)
    else:
        print("\nNo sitemap directive found in robots.txt.")

else:
    print("No robots.txt file found.")
