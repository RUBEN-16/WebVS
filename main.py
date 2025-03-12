from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as ec
from selenium.common.exceptions import InvalidArgumentException, TimeoutException, NoSuchElementException, WebDriverException,  NoAlertPresentException, StaleElementReferenceException
import time, requests

"""
LIMITATIONS: 
📜SQL Injection
    - CAPTCHA Protection: If the login form has a CAPTCHA, the script will fail to submit the form.
    - CSRF Tokens: Some forms include CSRF tokens, which must be valid for the request to be processed
    - Limited Analyzing Detection: Only check for keywords like "successful", "congratulation", and "welcome". (Especially for LOGIN forms)
    
📜XXS
    - Input and textarea HTML tags are covered to find and test the XSS vulnerabilities
    - Only one kind of payload used but in different variation to bypass the filterations
    - It's a Reflected XSS type testing. Other types are not covered
    
📜Security Header
    - 
"""

# Make non-visible UI to increase the effiency of process and reduce CPU usage
# chrome_options = Options()
# chrome_options.add_argument("--headless")  # Run in headless mode (no UI)
# chrome_options.add_argument("--disable-gpu")  # Recommended for headless mode
# chrome_options.add_argument("--window-size=1920x1080")  # Set a fixed screen size
# chrome_options.add_argument("--no-sandbox")  # Bypass OS-level security checks
# chrome_options.add_argument("--disable-dev-shm-usage")  # Prevent memory issues

# Automatically install and set up ChromeDriver
service = Service(ChromeDriverManager().install()) # service = Service(executable_path="chromedriver.exe") Manual and make sure chromedriver have been installe and locate in the same directory/folder

RED = '\033[91m'
GREEN = '\033[92m'
RESET = '\033[0m'

# Using to load the payloads from the text file into list
def loadIntoList(fileName): 
    list = []
    with open(fileName, 'r') as payloads:
        for line in payloads:
            list.append(line.strip())
            
    return list
            
# SQL vulnerability testing function
def sqliTesting(driver, url):
    print(f"🔄 Checking for SQL injection vulnerabilities on {url}...\n")
    
    # Common SQLi payloads
    sqli_payloads = loadIntoList('sqlInjections.txt')

    # Find all forms on the page
    forms = driver.find_elements(By.TAG_NAME, "form")
    
    if not forms:
        print("No forms found on the page.\n")
        return
    
    for form_index, form in enumerate(forms):
        print(f"\n🔍 Analyzing form {form_index + 1}...")
        
        # Find all input fields in the form (Make sure all the input filled in the form before submitting)
        inputs = form.find_elements(By.TAG_NAME, "input")
        textareas = form.find_elements(By.TAG_NAME, "textarea")
        all_inputs = inputs + textareas
        
        if not all_inputs:
            print("No input fields found in this form.\n")
            continue
        
        # Inject payloads into each input field
        for payload in sqli_payloads:
            print(f"Testing payload: {payload}")
            
            try:
                # Fill all input fields with the payload
                for input_field in all_inputs:
                    input_type = input_field.get_attribute("type")
                    if input_type not in ["hidden", "submit"]:  # Skip hidden and submit inputs
                        input_field.clear()
                        input_field.send_keys(payload)
                
                # Find the submit button and click it
                submit_button = form.find_element(By.XPATH, ".//input[@type='submit' or @type='button'] | .//button[@type='submit']")
                submit_button.click()
                
                # Wait for the page to load after submission
                WebDriverWait(driver, 5).until(
                    ec.presence_of_element_located((By.TAG_NAME, "body"))
                )
                
               # Analyze the response for signs of SQLi vulnerability
                if "successful" in driver.page_source.lower() or "congratulation" in driver.page_source.lower():
                    print(f"🚨 {RED}Potential SQLi vulnerability detected with payload: {payload}{RESET}\n")
                else:
                    if "please" in driver.page_source.lower() or "failed" in driver.page_source.lower() or "error" in driver.page_source.lower() or "invalid" in driver.page_source.lower() :
                        print(f"✅ {GREEN}No SQLi vulnerability detected with payload: {payload}{RESET}\n")
                    else:
                        print(f"🛠️ Analyzed but result not sure with payload: {payload}\n")
                    
                # Go back to the original page for the next test
                if driver.current_url != url:
                    driver.back()
                    WebDriverWait(driver, 5).until(
                        ec.presence_of_element_located((By.TAG_NAME, "body"))
                    )
                else:
                    # Re-locate the form and input elements to avoid stale references
                    forms = driver.find_elements(By.TAG_NAME, "form")
                    form = forms[form_index]  # Re-locate the current form
                    inputs = form.find_elements(By.TAG_NAME, "input")
                    textareas = form.find_elements(By.TAG_NAME, "textarea")
                    all_inputs = inputs + textareas
                
            except Exception as e:
                print(f"❌ Error testing payload {payload}: {e}\n")
                continue
          

def XXSChecker(driver, url):
    print(f"🔄 Checking for XSS vulnerabilities on {url}...\n")
    
    xxs_payloads = loadIntoList("xxsPayloads.txt")
    
    forms = driver.find_elements(By.TAG_NAME, "form")
    
    if not forms:
        print("No forms are found!")
        return
    
    for index, form in enumerate(forms):
        name = form.get_attribute("name") 
        form_id = name if name else (index + 1)
        print(f'\n🔍 Analyzing form [{form_id}]')
        
        inputs = form.find_elements(By.TAG_NAME, "input")
        text_areas = form.find_elements(By.TAG_NAME, "textarea")
        all_inputs = inputs + text_areas
        
        if not all_inputs:
            print(f"There's no input fields in the form [{form_id}]")
            continue
        
        for payload in xxs_payloads:
            print(f"Testing payload: {payload}")
            
            try:
                # Re-locate the form and input elements to avoid stale references
                forms = driver.find_elements(By.TAG_NAME, "form")
                form = forms[index]
                inputs = form.find_elements(By.TAG_NAME, "input")
                text_areas = form.find_elements(By.TAG_NAME, "textarea")
                all_inputs = inputs + text_areas
                
                # Fill all input fields with the payload
                for input_field in all_inputs:
                    input_type = input_field.get_attribute("type")
                    if input_type not in ["hidden", "submit"]:
                        input_field.clear()
                        input_field.send_keys(payload)
                
                # Submit the form
                submit_button = form.find_element(By.XPATH, ".//input[@type='submit' or @type='button'] | .//button[@type='submit']")
                submit_button.click()
                
                # Handle alerts (if any)
                try:
                    # Wait for an alert to be present
                    WebDriverWait(driver, 5).until(ec.alert_is_present())
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()  # Accept the alert
                    print(f"🚨 {RED}XSS vulnerability detected with payload: {payload} (Alert text: {alert_text}){RESET}\n")
                except TimeoutException:
                    if payload in driver.page_source:
                        print(f"🚨 {RED}Potential XSS vulnerability detected with payload: {payload}{RESET}\n")
                    else:
                        if "error" in driver.page_source or "failed" in driver.page_source:
                            print(f"✅ {GREEN}No XSS vulnerability detected with payload: {payload}{RESET}\n")
                        else:
                            print(f"🛠️ Analyzed but result not sure with payload: {payload}\n")
                        
                # Go back to the original page for the next test
                if driver.current_url != url:
                    driver.back()
                    WebDriverWait(driver, 5).until(
                        ec.presence_of_element_located((By.TAG_NAME, "body"))
                    )
            
            except StaleElementReferenceException:
                print(f"🔄 Stale element reference encountered. Re-locating elements and retrying payload: {payload}\n")
                continue
            except Exception as e:
                print(f"❌ Error testing payload {payload}: {e}\n")
                continue

    
def securityHeaderChecker(url):
    print(f"🔄 Checking for Security Headers on {url}...\n")
    SECURITY_HEADERS = loadIntoList('secHeaders.txt')
    
    html = requests.get(url)
    header = html.headers
    
    for policy in SECURITY_HEADERS:
        print(f"Scanning for {policy}")
        if policy not in header:
            print(f"🚨 {RED}{policy} is not in the header of the website{RESET}\n")
        else:
            print(f"✅ {GREEN}{policy} is found in the header of the website{RESET}\n")





# Soon...

def loginBruteForce(driver, url):
    pass
def APITesting(driver, url):
    pass
def rateLimitChecker(driver, url):
    pass
def portsChecker(driver, url):
    pass




print("\n🌐 WELCOME TO WEB VULNERABILITY CHECKER 🌐\n")
while True:
    driver = webdriver.Chrome(service=service)#, options=chrome_options)
    url_input = input("Enter URL (or '0' to exit): ").strip()
    
    if not url_input:
        print("⚠️ No input provided. Please enter a URL.\n")
        continue
    
    if url_input == "0":
        print("Exiting program. Goodbye!\n")
        break

    try:
        print(f"🔎 Scanning {url_input}...\n")
        driver.get(url_input)  # Navigate to the URL
        
        # Wait for the page to load
        WebDriverWait(driver, 5).until(
            ec.presence_of_element_located((By.TAG_NAME, "body"))
        )
        
        # Perform SQLi check
        # sqliTesting(driver, url_input)
        # XXSChecker(driver, url_input)
        securityHeaderChecker(url_input)
        time.sleep(10)
        break  # Exit loop after first successful scan

    except InvalidArgumentException:
        print("⚠️ Invalid URL format! Make sure to include 'http://' or 'https://'.\n")
    except TimeoutException:
        print("⏳ Request timed out! The server took too long to respond.\n")
    except NoSuchElementException:
        print("❌ Unable to find an element on the page! Check the page structure.\n")
    except WebDriverException as e:
        print(f"❌ An error occurred: {e}\n")
    finally:
        # Close the browser
        driver.quit()