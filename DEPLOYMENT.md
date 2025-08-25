# 🚀 Deployment Guide - PCAP Security Analyzer

This guide will walk you through deploying your PCAP Security Analyzer to GitHub and Vercel.

## 📋 Prerequisites

Before starting, ensure you have:

- [ ] Git installed and configured
- [ ] GitHub account
- [ ] Vercel account (free tier available)
- [ ] Python 3.10+ installed locally
- [ ] All project files ready

## 🌐 Step 1: GitHub Repository Setup

### 1.1 Create a New Repository

1. Go to [GitHub](https://github.com) and sign in
2. Click the "+" icon in the top right corner
3. Select "New repository"
4. Fill in the repository details:
   - **Repository name**: `pcap-security-analyzer`
   - **Description**: Professional PCAP analysis tool with threat detection and risk assessment
   - **Visibility**: Choose Public or Private
   - **Initialize with**: Don't add any files (we'll push our existing code)
5. Click "Create repository"

### 1.2 Prepare Your Local Repository

Open your terminal/command prompt in your project directory and run:

```bash
# Initialize git repository (if not already done)
git init

# Add all files
git add .

# Make initial commit
git commit -m "Initial commit: PCAP Security Analyzer"

# Add remote origin (replace with your repository URL)
git remote add origin https://github.com/YOUR_USERNAME/pcap-security-analyzer.git

# Set main branch and push
git branch -M main
git push -u origin main
```

### 1.3 Verify GitHub Setup

- Go to your GitHub repository
- Verify all files are uploaded
- Check that the repository is accessible

## 🚀 Step 2: Vercel Deployment

### 2.1 Connect Vercel to GitHub

1. Go to [Vercel](https://vercel.com) and sign in
2. Click "New Project"
3. Import your GitHub repository:
   - Select "Import Git Repository"
   - Find and select your `pcap-security-analyzer` repository
   - Click "Import"

### 2.2 Configure Project Settings

Vercel will automatically detect your Python configuration. The settings should be:

- **Framework Preset**: Other
- **Root Directory**: `./` (root)
- **Build Command**: Leave empty (Vercel will auto-detect)
- **Output Directory**: Leave empty (Vercel will auto-detect)
- **Install Command**: `pip install -r requirements.txt`

### 2.3 Environment Variables

Add these environment variables in Vercel:

```bash
FLASK_ENV=production
FLASK_DEBUG=false
MAX_CONTENT_LENGTH=100000000
```

### 2.4 Deploy

1. Click "Deploy"
2. Wait for the build to complete
3. Your app will be available at: `https://your-project.vercel.app`

## 🔧 Step 3: Post-Deployment Configuration

### 3.1 Custom Domain (Optional)

1. In your Vercel project dashboard, go to "Settings" → "Domains"
2. Add your custom domain
3. Follow the DNS configuration instructions

### 3.2 Environment Variables

You can add more environment variables in Vercel:

```bash
# Security
SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=your-domain.com

# Database (if using)
DATABASE_URL=your-database-url

# External APIs (if using)
API_KEY=your-api-key
```

### 3.3 Function Configuration

Vercel automatically configures your Flask app as serverless functions. The `vercel.json` file handles:

- **Build Configuration**: Python app detection
- **Routing**: All requests to your Flask app
- **Function Settings**: 30-second timeout for analysis

## 📊 Step 4: Monitoring & Maintenance

### 4.1 Vercel Analytics

- **Analytics**: Monitor performance and usage
- **Functions**: Check serverless function execution
- **Logs**: View application logs and errors

### 4.2 GitHub Actions (Optional)

The included `.github/workflows/ci.yml` provides:

- **Automated Testing**: Python 3.10 and 3.11
- **Code Quality**: Linting and formatting checks
- **Security Audits**: Bandit and Safety checks
- **Auto-deployment**: Deploy to Vercel on main branch push

To enable GitHub Actions:

1. Go to your repository → "Actions"
2. Enable GitHub Actions
3. Add Vercel secrets:
   - `VERCEL_TOKEN`: Get from Vercel account settings
   - `ORG_ID`: Your Vercel organization ID
   - `PROJECT_ID`: Your Vercel project ID

## 🚨 Troubleshooting

### Common Issues

#### Build Failures

**Problem**: Vercel build fails
**Solution**: 
- Check `requirements.txt` for version conflicts
- Ensure all dependencies are compatible with Python 3.10
- Check for missing system dependencies

#### Import Errors

**Problem**: Module import errors in Vercel
**Solution**:
- Verify `vercel.json` configuration
- Check Python path settings
- Ensure all imports use relative paths correctly

#### Function Timeouts

**Problem**: Analysis times out
**Solution**:
- Large PCAP files may exceed 30-second limit
- Consider implementing chunked processing
- Add progress indicators for long operations

#### Memory Issues

**Problem**: Out of memory errors
**Solution**:
- Optimize memory usage in analysis functions
- Implement streaming for large files
- Add memory monitoring and limits

### Debugging Tips

1. **Check Vercel Logs**: Function logs show detailed error information
2. **Local Testing**: Test with same Python version locally
3. **Dependency Check**: Verify all packages install correctly
4. **Environment Variables**: Ensure all required variables are set

## 🔒 Security Considerations

### Production Security

1. **Environment Variables**: Never commit secrets to Git
2. **File Uploads**: Implement proper file validation
3. **Rate Limiting**: Consider adding rate limiting for uploads
4. **Authentication**: Add user authentication if needed
5. **HTTPS**: Vercel provides automatic HTTPS

### Security Headers

Vercel automatically adds security headers, but you can customize them in `vercel.json`:

```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "X-XSS-Protection",
          "value": "1; mode=block"
        }
      ]
    }
  ]
}
```

## 📈 Performance Optimization

### Vercel Optimizations

1. **Function Cold Starts**: Keep functions warm with regular requests
2. **Dependency Optimization**: Minimize package size
3. **Caching**: Implement caching for repeated analyses
4. **CDN**: Vercel provides global CDN automatically

### Application Optimizations

1. **Async Processing**: Use background tasks for long operations
2. **Memory Management**: Implement proper cleanup
3. **File Handling**: Stream large files instead of loading entirely
4. **Database**: Use connection pooling if applicable

## 🔄 Continuous Deployment

### Automated Deployment

With GitHub Actions enabled:

1. **Push to main branch** → Automatic deployment
2. **Pull requests** → Run tests and checks
3. **Security scans** → Automated vulnerability checks
4. **Quality gates** → Ensure code quality before deployment

### Deployment Strategies

1. **Blue-Green**: Deploy new version alongside old
2. **Rolling Updates**: Gradual deployment across instances
3. **Canary Releases**: Test with small user group first

## 📚 Additional Resources

### Documentation

- [Vercel Python Documentation](https://vercel.com/docs/functions/serverless-functions/runtimes/python)
- [Flask Deployment Guide](https://flask.palletsprojects.com/en/2.3.x/deploying/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)

### Community

- [Vercel Community](https://github.com/vercel/vercel/discussions)
- [GitHub Community](https://github.com/orgs/community/discussions)
- [Flask Community](https://flask.palletsprojects.com/en/2.3.x/community/)

---

## 🎉 Congratulations!

You've successfully deployed your PCAP Security Analyzer to GitHub and Vercel! 

Your application is now:
- ✅ Version controlled on GitHub
- ✅ Deployed and accessible online
- ✅ Configured for continuous deployment
- ✅ Ready for production use

### Next Steps

1. **Test your deployment** with sample PCAP files
2. **Monitor performance** using Vercel analytics
3. **Set up monitoring** for production use
4. **Share your project** with the cybersecurity community

---

**Need help?** Check the troubleshooting section or open an issue on GitHub!
