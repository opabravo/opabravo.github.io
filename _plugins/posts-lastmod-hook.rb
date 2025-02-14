#!/usr/bin/env ruby
#
# Check for changed posts

[:documents, :pages].each do |hook|
  Jekyll::Hooks.register hook, :post_render do |item|
    if item.output_ext == ".html"
      content = item.output
      site_url = item.site.config['url']
      whitelist = ['mailto:', 'tel:']  # whitelist domains
      # Add rel="nofollow noopener noreferrer" to external anchor tags and ref parameter
      content.gsub!(%r{<a\s+href="((?!#{whitelist.map { |d| Regexp.escape(d) }.join('|')})[^"]+)"(?![^>]*rel=)}, 
                    "<a href=\"\\1?ref=#{site_url.gsub('https://', '')}\" target=\"_blank\" rel=\"nofollow noopener noreferrer\"")
      # Update the item content
      item.output = content
    end
  end
end