import pandas as pd
from openpyxl import Workbook
import boto3
from datetime import timedelta, timezone
import datetime
import pytz

indian_timezone = pytz.timezone('Asia/Kolkata')

def create_ecr_vulnerabilities_excel_sheet():
    # AWS profile and region
    aws_profile = 'prod'
    aws_region = 'ap-south-1'

    # Connect to AWS ECR using the profile
    session = boto3.Session(profile_name=aws_profile)
    ecr_client = session.client('ecr', region_name=aws_region)

    # Fetch all repositories
    response = ecr_client.describe_repositories()
    repositories = response['repositories']

    # Iterate over repositories
    all_data = []
    for repository in repositories:
        repository_name = repository['repositoryName']

        # Fetch images in the repository
        image_response = ecr_client.describe_images(
            repositoryName=repository_name
        )

        # Sort images by image push timestamp (most recent first)
        images = sorted(image_response['imageDetails'], key=lambda x: x['imagePushedAt'], reverse=True)

        # Fetch vulnerabilities for the most recent image
        if images:
            image = images[0]
            if 'imageTags' in image:
                image_tags = str(image['imageTags'])
            else:
                image_tags="UNTAGGED"
            image_pushed_at = image['imagePushedAt']
            
            try:
                response = ecr_client.describe_image_scan_findings(
                    repositoryName=repository_name,
                    imageId={'imageDigest': image['imageDigest']}
                )
     

                if 'findingSeverityCounts' in response['imageScanFindings']:
                    findings = response['imageScanFindings']['findingSeverityCounts']
                    print(findings)
                    
                    
                    critical_count = findings.get('CRITICAL', 0)
                    high_count = findings.get('HIGH', 0)
                    medium_count = findings.get('MEDIUM', 0)
                    low_count = findings.get('LOW', 0)

                    # Convert image_pushed_at to timezone-unaware format
                    image_pushed_at = image_pushed_at.astimezone(indian_timezone)
                    image_pushed_at = image_pushed_at.replace(tzinfo=None)
                    
                    print(image_pushed_at)

                    row = {
                        'Repository': repository_name,
                        'Image Tag': image_tags,
                        'Published At': image_pushed_at,
                        'Critical': critical_count,
                        'High': high_count,
                        'Medium': medium_count,
                        'Low': low_count
                    }
                    all_data.append(row)
                    print(row)

            except ecr_client.exceptions.ScanNotFoundException:
                print('wrong ...')
                continue

    # Create DataFrame and Excel sheet
    df = pd.DataFrame(all_data)
    print(df)
    excel_file = 'ecr_vulnerabilities.xlsx'
    df.to_excel(excel_file, index=False)
    print(f"Excel sheet '{excel_file}' created successfully.")


# Call the function
create_ecr_vulnerabilities_excel_sheet()
