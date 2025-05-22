# Chronicle API Regions

When initializing the Chronicle client, you need to specify the `region` parameter corresponding to where your Chronicle instance is installed. Use the lowercase version of one of the following values:

| Region Code | Description |
|-------------|-------------|
| `us` | United States - multi-region |
| `europe` | Europe (Default European region) |
| `asia_southeast1` | Singapore |
| `europe_west2` | London |
| `australia_southeast1` | Sydney |
| `me_west1` | Israel |
| `europe_west6` | Zurich |
| `europe_west3` | Frankfurt |
| `me_central2` | Dammam |
| `asia_south1` | Mumbai |
| `asia_northeast1` | Tokyo |
| `northamerica_northeast2` | Toronto |
| `europe_west12` | Turin |
| `me_central1` | Doha |
| `southamerica_east1` | Sao Paulo |
| `europe_west9` | Paris |
| `dev` | Development environment (sandbox) |
| `staging` | Staging environment (sandbox) |

## Special Environments

The `dev` and `staging` regions are special environments used for testing and development purposes:

- `dev`: Development environment using the URL `https://dev-chronicle.sandbox.googleapis.com`
- `staging`: Staging environment using the URL `https://staging-chronicle.sandbox.googleapis.com`

Note that these environments use a slightly different instance ID format internally.

## Usage Example

```python
# Initialize Chronicle client with the appropriate region
chronicle = client.chronicle(
    customer_id="your-chronicle-instance-id",
    project_id="your-project-id",
    region="us"  # Use lowercase region code from the table above
)

# For staging environment
staging_chronicle = client.chronicle(
    customer_id="ebdc4bb9-878b-11e7-8455-10604b7cb5c1", 
    project_id="malachite-catfood-byop-staging",
    region="staging"
)
```

Always use the lowercase version of the region code when configuring your Chronicle client. 