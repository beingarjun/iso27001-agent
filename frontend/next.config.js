/** @type {import('next').NextConfig} *//** @type {import('next').NextConfig} *//** @type {import('next').NextConfig} */

const nextConfig = {

  reactStrictMode: true,const nextConfig = {const nextConfig = {

  experimental: { appDir: true },

  env: {  reactStrictMode: true,  reactStrictMode: true,

    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',

  },  swcMinify: true,  swcMinify: true,

  async rewrites() {

    return [{ source: '/api/:path*', destination: `${process.env.NEXT_PUBLIC_API_URL}/:path*` }];  experimental: {  

  },

};    appDir: true,  // Environment variables



module.exports = nextConfig;  },  env: {

  env: {    CUSTOM_KEY: 'my-value',

    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',  },

    NEXT_PUBLIC_APP_NAME: 'ISO 27001 Compliance Agent',  

    NEXT_PUBLIC_APP_DESCRIPTION: 'Enterprise GRC platform with AI governance',  // API routes configuration

  },  async headers() {

  images: {    return [

    domains: ['localhost'],      {

  },        source: '/api/:path*',

  async rewrites() {        headers: [

    return [          {

      {            key: 'Access-Control-Allow-Origin',

        source: '/api/:path*',            value: 'http://localhost:8000',

        destination: `${process.env.NEXT_PUBLIC_API_URL}/:path*`,          },

      },          {

    ];            key: 'Access-Control-Allow-Methods',

  },            value: 'GET, POST, PUT, DELETE, OPTIONS',

  async headers() {          },

    return [          {

      {            key: 'Access-Control-Allow-Headers',

        source: '/(.*)',            value: 'Content-Type, Authorization',

        headers: [          },

          {        ],

            key: 'X-Frame-Options',      },

            value: 'DENY',    ]

          },  },

          {  

            key: 'X-Content-Type-Options',  // Image optimization

            value: 'nosniff',  images: {

          },    domains: ['localhost'],

          {  },

            key: 'Referrer-Policy',  

            value: 'strict-origin-when-cross-origin',  // Experimental features

          },  experimental: {

        ],    typedRoutes: true,

      },  }

    ];}

  },

};module.exports = nextConfig

module.exports = nextConfig;