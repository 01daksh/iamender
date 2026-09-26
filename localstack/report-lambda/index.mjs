export const handler = async () => ({
  statusCode: 200,
  body: JSON.stringify({
    service: "iamender-report-lambda",
    result: "report generated",
    bucket: process.env.REPORTS_BUCKET,
  }),
});
