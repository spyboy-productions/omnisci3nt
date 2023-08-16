import requests
import re

def extract_links_and_emails(url, timeout=10):
    try:
        response = requests.get(url, timeout=timeout)
        content = response.text

        # Pattern to match social media links
        social_media_pattern = r'(https?://(?:www\.)?(?:facebook|twitter|instagram)\.com/[^"\'>\s]+)'
        social_media_links = re.findall(social_media_pattern, content, re.IGNORECASE)

        # Pattern to match email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, content)

        return social_media_links, emails
    except requests.Timeout:
        return None, "Request timed out"
    except Exception as e:
        return None, str(e)


if __name__ == "__main__":
    website_url = input("Enter the website URL: ")
    social_media_links, emails = extract_links_and_emails(website_url)

    if social_media_links:
        print("Social media links:")
        for link in social_media_links:
            print(link)
    else:
        print("No social media links found or an error occurred.")

    if emails:
        print("\nEmail addresses:")
        for email in emails:
            print(email)
    else:
        print("No email addresses found or an error occurred.")
