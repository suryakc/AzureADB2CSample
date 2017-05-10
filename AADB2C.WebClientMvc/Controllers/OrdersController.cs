﻿using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace AADB2C.WebClientMvc.Controllers
{
    [Authorize]
    public class OrdersController : Controller
    {
        private static string serviceUrl = ConfigurationManager.AppSettings["api:OrdersApiUrl"];

        // GET: Orders
        public async Task<ActionResult> Index()
        {
            try
            {

                var bootstrapContext = ClaimsPrincipal.Current.Identities.First().BootstrapContext as System.IdentityModel.Tokens.BootstrapContext;

                HttpClient client = new HttpClient();

                client.BaseAddress = new Uri(serviceUrl);

                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bootstrapContext.Token);

                HttpResponseMessage response = await client.GetAsync("api/orders");

                if (response.IsSuccessStatusCode)
                {

                    var orders = await response.Content.ReadAsAsync<List<OrderModel>>();

                    return View(orders);
                }
                else
                {
                    // If the call failed with access denied, show the user an error indicating they might need to sign-in again.
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        return new RedirectResult("/Error?message=Error: " + response.ReasonPhrase + " You might need to sign in again.");
                    }
                }

                return new RedirectResult("/Error?message=An Error Occurred Reading Orders List: " + response.StatusCode);
            }
            catch (Exception ex)
            {
                return new RedirectResult("/Error?message=An Error Occurred Reading Orders List: " + ex.Message);
            }
        }

        public ActionResult Create()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Create([Bind(Include = "ShipperName,ShipperCity")]OrderModel order)
        {

            try
            {
                var bootstrapContext = ClaimsPrincipal.Current.Identities.First().BootstrapContext as System.IdentityModel.Tokens.BootstrapContext;

                HttpClient client = new HttpClient();

                client.BaseAddress = new Uri(serviceUrl);

                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bootstrapContext.Token);

                HttpResponseMessage response = await client.PostAsJsonAsync("api/orders", order);

                if (response.IsSuccessStatusCode)
                {
                    return RedirectToAction("Index");
                }
                else
                {
                    // If the call failed with access denied, show the user an error indicating they might need to sign-in again.
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        return new RedirectResult("/Error?message=Error: " + response.ReasonPhrase + " You might need to sign in again.");
                    }
                }

                return new RedirectResult("/Error?message=An Error Occurred Creating Order: " + response.StatusCode);
            }
            catch (Exception ex)
            {
                return new RedirectResult("/Error?message=An Error Occurred Creating Order: " + ex.Message);
            }

        }

    }

    public class OrderModel
    {
        public string OrderID { get; set; }
        [Display(Name = "Shipper")]
        public string ShipperName { get; set; }
        [Display(Name = "Shipper City")]
        public string ShipperCity { get; set; }
        public DateTimeOffset TS { get; set; }
    }
}
