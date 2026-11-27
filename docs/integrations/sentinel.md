# Microsoft Sentinel

Verdyx sends events to Microsoft Sentinel through the Azure Monitor **Logs
Ingestion API**: each event becomes a row in a custom table,
`VerdyxEvents_CL`, in your Sentinel workspace.

This needs four things on the Azure side: the table, a data collection
endpoint, a data collection rule, and an app that may write through the rule.
The commands below use the Azure CLI. Replace `<rg>`, `<workspace>` and
`<region>` with your resource group, Log Analytics workspace and its region.

## 1. Create the table

```bash
az monitor log-analytics workspace table create -g <rg> --workspace-name <workspace> \
  -n VerdyxEvents_CL --columns \
  TimeGenerated=datetime EventId=string EventType=string SubmissionId=string \
  Target=string Sha256=string IsMalicious=boolean Confidence=real \
  HuntName=string Rules=dynamic ReportUrl=string Data=dynamic
```

| Column | What it holds |
|---|---|
| `TimeGenerated` | When the event happened |
| `EventId` | The delivery id; the same event retried keeps it |
| `EventType` | `analysis.completed`, `analysis.updated`, `livehunt.match` or `webhook.test` |
| `SubmissionId`, `Target`, `Sha256` | The scan, the file name or URL, and the file's hash |
| `IsMalicious`, `Confidence` | The verdict (scans only) |
| `HuntName`, `Rules` | The live hunt and the YARA rules that matched (hunts only) |
| `ReportUrl` | Link to the report on verdyx.dev |
| `Data` | The whole event, as in the [event reference](../api/webhooks.md) |

## 2. Create the data collection endpoint

```bash
az monitor data-collection endpoint create -g <rg> -n verdyx-dce -l <region> \
  --public-network-access Enabled \
  --query "{id:id, url:logsIngestion.endpoint}"
```

Keep both values: the `url` is what Verdyx sends to.

## 3. Create the data collection rule

Save this as `verdyx-dcr.json`, filling in the endpoint `id` from step 2 and
your workspace's resource id
(`az monitor log-analytics workspace show -g <rg> -n <workspace> --query id`):

```json
{
  "location": "<region>",
  "properties": {
    "dataCollectionEndpointId": "<endpoint id>",
    "streamDeclarations": {
      "Custom-VerdyxEvents_CL": {
        "columns": [
          { "name": "TimeGenerated", "type": "datetime" },
          { "name": "EventId", "type": "string" },
          { "name": "EventType", "type": "string" },
          { "name": "SubmissionId", "type": "string" },
          { "name": "Target", "type": "string" },
          { "name": "Sha256", "type": "string" },
          { "name": "IsMalicious", "type": "boolean" },
          { "name": "Confidence", "type": "real" },
          { "name": "HuntName", "type": "string" },
          { "name": "Rules", "type": "dynamic" },
          { "name": "ReportUrl", "type": "string" },
          { "name": "Data", "type": "dynamic" }
        ]
      }
    },
    "destinations": {
      "logAnalytics": [{ "workspaceResourceId": "<workspace resource id>", "name": "sentinel" }]
    },
    "dataFlows": [
      {
        "streams": ["Custom-VerdyxEvents_CL"],
        "destinations": ["sentinel"],
        "transformKql": "source",
        "outputStream": "Custom-VerdyxEvents_CL"
      }
    ]
  }
}
```

```bash
az monitor data-collection rule create -g <rg> -n verdyx-dcr --rule-file verdyx-dcr.json \
  --query "{id:id, immutableId:immutableId}"
```

Keep the `immutableId` (it looks like `dcr-0123…`) and the `id`.

## 4. Create the app and let it write

```bash
az ad sp create-for-rbac -n verdyx-sentinel-ingest --query "{tenant:tenant, clientId:appId, clientSecret:password}"
az role assignment create --assignee <clientId> --role "Monitoring Metrics Publisher" --scope <rule id>
```

The role can take up to 30 minutes to apply. Until then, deliveries fail with
HTTP 403 and are retried.

## 5. In Verdyx: add the destination

On your profile page, open the **API and webhooks** tab and choose **Microsoft Sentinel**, then fill in:

| Field | Value |
|---|---|
| Logs Ingestion endpoint | the `url` from step 2 |
| Client secret | `clientSecret` from step 4. Stored encrypted, never shown again |
| Tenant ID | `tenant` from step 4 |
| Client ID | `clientId` from step 4 |
| Rule immutable ID | `immutableId` from step 3 |
| Stream | leave empty for `Custom-VerdyxEvents_CL` |

Press **Test**. HTTP 204 means Azure accepted the row. It shows up in the
table within a few minutes.

Or with the API:

```bash
curl -X POST https://api.verdyx.dev/api/v1/webhooks \
  -H "X-API-Key: $VERDYX_API_KEY" -H "Content-Type: application/json" \
  -d '{"kind":"sentinel","url":"https://verdyx-dce-xxxx.<region>-1.ingest.monitor.azure.com",
       "credential":"<client secret>",
       "config":{"tenantId":"<tenant>","clientId":"<clientId>","dcrImmutableId":"dcr-…"},
       "events":["analysis.completed","livehunt.match"]}'
```

## 6. Query and alert

```kusto
VerdyxEvents_CL
| where EventType == "analysis.completed" and IsMalicious
| project TimeGenerated, Target, Sha256, Confidence, ReportUrl
```

To raise Sentinel incidents, create a **scheduled analytics rule** with a query
like the one above, for example every 5 minutes over the last 5 minutes, and
map `Sha256` to a FileHash entity.

## If it doesn't arrive

The destination's **Delivery logs** say what went wrong:

| Result | Meaning |
|---|---|
| Entra ID refused the app (HTTP 401, invalid_client) | The client secret is wrong or expired. |
| Entra ID refused the app (HTTP 400, unauthorized_client) | The tenant or client ID is wrong. |
| HTTP 403: needs the Monitoring Metrics Publisher role | Step 4's role isn't assigned yet, or is on the wrong rule. |
| HTTP 404: rule or stream wasn't found | The immutable ID or stream name is wrong, or the rule isn't linked to this endpoint. |
| HTTP 400: the stream's columns don't match | The rule's stream declaration differs from step 3. |

Azure Government (`.ingest.monitor.azure.us`) and Azure China
(`.ingest.monitor.azure.cn`) endpoints work too: Verdyx signs in to the
matching cloud.
