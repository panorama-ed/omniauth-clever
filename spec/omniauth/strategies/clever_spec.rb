require 'spec_helper'
require 'omniauth-clever'
require "rack/test"

RSpec.describe OmniAuth::Strategies::Clever do
  include Rack::Test::Methods

  let(:app) do
    Rack::Builder.new do
      use OmniAuth::Test::PhonySession
      use OmniAuth::Builder do
        provider :clever, "TEST_ID", "TEST_SECRET"
      end
      run lambda { |env|
        [
          404,
          { "Content-Type" => "text/plain" },
          [env.key?("omniauth.auth").to_s]
        ]
      }
    end
  end

  subject(:strategy) do
    described_class.new(app, "TEST_ID", "TEST_SECRET").tap do |strategy|
      strategy.options.client_options.site = 'https://api.clever.com'
    end
  end

  before(:each) do
    OmniAuth.config.test_mode = true
    env = { 'rack.session' => {} }
    request = double("Request",
                     params: {},
                     env: env,
                     scheme: 'http',
                     url: 'http://example.org',
                     path: '')
    allow(strategy).to receive(:request).and_return(request)
    strategy.call!(env)
  end

  after(:each) do
    OmniAuth.config.test_mode = false
  end

  context 'client options' do
    it 'should have correct name' do
      expect(subject.options.name).to eq('clever')
    end

    it 'should have correct site' do
      expect(subject.options.client_options.site).to eq('https://api.clever.com')
    end

    it 'should have correct authorize url' do
      expect(subject.options.client_options.authorize_url).to eq('https://clever.com/oauth/authorize')
    end

    it 'should have correct token url' do
      expect(subject.options.client_options.token_url).to eq('https://clever.com/oauth/tokens')
    end

    it 'should have provider ignores state set to true' do
      expect(subject.options.provider_ignores_state).to be true
    end
  end

  describe '#token_params' do
    it 'should include Authorization header' do
      token_params = subject.token_params
      expect(token_params[:headers]).to include('Authorization')
    end

    it 'should encode client_id and client_secret in Authorization header' do
      encoded_credentials = Base64.strict_encode64("#{subject.options.client_id}:#{subject.options.client_secret}")
      token_params = subject.token_params
      expect(token_params[:headers]['Authorization']).to eq("Basic #{encoded_credentials}")
    end
  end

  describe '#uid' do
    let(:raw_info) do
      {
        'data' => {
          'id' => '12345'
        }
      }
    end

    before do
      allow(subject).to receive(:raw_info).and_return(raw_info)
    end

    it 'returns the id from raw_info' do
      expect(subject.uid).to eq('12345')
    end
  end

  describe '#info' do
    let(:raw_info) do
      {
        'type' => 'student',
        'data' => {
          'id' => '12345',
          'name' => 'John Doe'
        }
      }
    end

    before do
      allow(subject).to receive(:raw_info).and_return(raw_info)
    end

    it 'returns the user type and data from raw_info' do
      expect(subject.info).to eq({
                                   :user_type => 'student',
                                   'id' => '12345',
                                   'name' => 'John Doe'
                                 })
    end
  end

  describe '#extra' do
    let(:raw_info) do
      {
        'data' => {
          'id' => '12345'
        }
      }
    end

    before do
      allow(subject).to receive(:raw_info).and_return(raw_info)
    end

    it 'returns the raw_info' do
      expect(subject.extra).to eq({
                                    'raw_info' => raw_info
                                  })
    end
  end

  describe '#raw_info' do
    let(:access_token) { double('AccessToken', get: double('Response', parsed: 'response')) }

    before do
      allow(subject).to receive(:access_token).and_return(access_token)
    end

    it 'returns the parsed response from the access token' do
      expect(subject.raw_info).to eq('response')
    end
  end

  describe '#callback_url' do
    before do
      allow(subject).to receive(:full_host).and_return('http://localhost:3000')
      allow(subject).to receive(:script_name).and_return('/auth')
      allow(subject).to receive(:callback_path).and_return('/callback')
    end

    it 'returns the correct callback url' do
      expect(subject.callback_url).to eq('http://localhost:3000/auth/callback')
    end
  end

  describe '#callback_phase' do
    context 'when there is an error parameter' do
      it 'fails with the error provided' do
        allow(strategy.request).to receive(:params).and_return('error' => 'access_denied', 'error_description' => 'User denied your request')
        expect(strategy).to receive(:fail!).with('access_denied', instance_of(OmniAuth::Strategies::OAuth2::CallbackError))
        strategy.callback_phase
      end
    end

    context 'when CSRF attack is detected' do
      it 'fails with CSRF detected' do
        strategy.session['omniauth.state'] = 'state123'
        allow(strategy.request).to receive(:params).and_return('state' => 'state456')
        expect(strategy).to receive(:fail!).with(:csrf_detected, instance_of(OmniAuth::Strategies::OAuth2::CallbackError))
        strategy.callback_phase
      end
    end
  end
end
