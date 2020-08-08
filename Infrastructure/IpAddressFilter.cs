using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;

namespace IpAddressHandlerExample.Infrastructure
{
    public class IpAddressFilter : ActionFilterAttribute
    {
        private readonly ILogger<IpAddressFilter> _logger;
        private readonly string _safelist;

         public IpAddressFilter(string safelist, ILogger<IpAddressFilter> logger)
        {
            _safelist = safelist;
            _logger = logger;
        }     

        public override void OnActionExecuting(ActionExecutingContext context)
        {
            var remoteIp = context.HttpContext.Connection.RemoteIpAddress;
            _logger.LogDebug("Remote IpAddress: {RemoteIp}", remoteIp);
            var ip = _safelist.Split(';');
            var badIp = true;
            
            if (remoteIp.IsIPv4MappedToIPv6)
            {
                remoteIp = remoteIp.MapToIPv4();
            }
            
            foreach (var address in ip)
            {
                if (!string.IsNullOrWhiteSpace(address))
                {
                    var testIp = IPAddress.Parse(address);

                    if (testIp.Equals(remoteIp))
                    {
                        badIp = false;
                        break;
                    }
                }
            }

            if (badIp)
            {
                _logger.LogWarning("Forbidden Request from IP: {RemoteIp}", remoteIp);
                context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
                return;
            }

            base.OnActionExecuting(context);
        }
    }
}