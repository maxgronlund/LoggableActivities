# frozen_string_literal: true

require_relative 'lib/loggable_activity/version'

Gem::Specification.new do |spec|
  spec.name = 'loggable_activity'
  spec.version = LoggableActivity::VERSION
  spec.authors = ['Max Groenlund']
  spec.email = ['max@synthmax.dk']

  spec.summary = 'Activity Logger: Fast, easy-to-use, full-featured logging with privacy protection and graphical representation'
  spec.description = <<-DESC
    LoggableActivity is a powerful gem for Ruby on Rails that provides seamless activity logging
    prepared for GDPR compliance and supporting record relations. It allows you to effortlessly
    keep track of user actions within your application, capturing who did what and when, even with
    related records included in the logs. With LoggableActivity, you can maintain the privacy of
    sensitive information in your logs, making it a perfect solution for applications that require
    robust audit trails while adhering to strict data protection regulations.
    Without any hassle you can easily visualize the logs in a graphical representation,
    or build your own custom views.
    Data can be exported in csv format for a given record. Eg. a user, a company, a project etc.
  DESC
  spec.homepage = 'https://loggableactivity-efe7b931c886.herokuapp.com/'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.2.0'

  # spec.metadata["allowed_push_host"] = "TODO: Set to your gem server 'https://example.com'"

  spec.metadata = {
    'homepage_uri' => 'https://loggableactivity-efe7b931c886.herokuapp.com/',
    'source_code_uri' => 'https://github.com/LoggableActivity/LoggableActivity',
    'changelog_uri' => 'https://github.com/LoggableActivity/LoggableActivity/blob/main/CHANGELOG.md',
    'documentation_uri' => 'https://LoggableActivity.github.io/LoggableActivity/',
    'rubygems_mfa_required' => 'true'
  }

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git appveyor Gemfile])
    end
  end
  spec.bindir = 'exe'
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'activerecord', '~> 7.1.3'
  spec.add_dependency 'bunny', '~> 2.23'
  spec.add_dependency 'json-schema', '~> 4.1', '>= 4.1.1'
  spec.add_dependency 'kaminari', '~> 1.2', '>= 1.2.2'
  spec.add_dependency 'rails', '~> 7.1.2'
  spec.add_dependency 'sassc-rails', '~> 2.1', '>= 2.1.2'
  spec.add_dependency 'slim-rails', '~> 3.6', '>= 3.6.3'

  # spec.add_development_dependency 'generator_spec', '~> 0.10.0'

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
  spec.metadata['rubygems_mfa_required'] = 'true'
end
