using System;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Net.Http;
using System.Net;
using System.Linq;

namespace IpAddressHandlerExample.Infrastructure
{
    public class IpAddressMiddlerWare
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<IpAddressMiddlerWare> _logger;
        private readonly string _safelist;

        public IpAddressMiddlerWare(RequestDelegate next,
            ILogger<IpAddressMiddlerWare> logger,
            string safelist)
        {
            _safelist = safelist;
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context)
        {          
            var remoteIp = context.Connection.RemoteIpAddress;
            _logger.LogDebug("Request from Remote IP address: {RemoteIp}", remoteIp);

            string[] ip = _safelist.Split(';');

            var bytes = remoteIp.GetAddressBytes();
            var badIp = true;
            if (ip.Length > 0)
            {
                foreach (var address in ip)
                {
                    if (!string.IsNullOrWhiteSpace(address))
                    {
                        var testIp = IPAddress.Parse(address);
                        if (testIp.GetAddressBytes().SequenceEqual(bytes))
                        {
                            badIp = false;
                            break;
                        }
                    }
                }
            }

            if (badIp)
            {
                _logger.LogWarning(
                    "Forbidden Request from Remote IP address: {RemoteIp}", remoteIp);
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
        
            await _next.Invoke(context);
        }
    }
}
