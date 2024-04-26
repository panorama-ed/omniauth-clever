require 'spec_helper'
require 'omniauth-clever'
require "rack/test"

RSpec.describe OmniAuth::Strategies::Clever do
  include Rack::Test::Methods

  subject(:strategy) do
    described_class.new(app, :clever)
  end

  subject do
    OmniAuth::Strategies::Clever.new({})
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

  describe '#callback_phase' do
    let(:request) { double('Request', params: {}, env: {}) }
    let(:app) do
      lambda do |env|
        [200, {}, ["Hello."]]
      end
    end

    before do
      allow(subject).to receive(:request).and_return(request)
      allow(request).to receive(:scheme).and_return("http")
      allow(request).to receive(:url).and_return("http://localhost")
      allow(strategy).to receive(:full_host).and_return("http://example.com")
      allow(strategy).to receive(:script_name).and_return("")
      allow(strategy).to receive(:callback_path).and_return("/auth/rainbow/callback")
      subject.instance_variable_set("@env", {"rack.session" => {}})
    end

    context 'when error is present in request params' do
      # before do
      #   request.params["error_reason"] = "some_error"
      # end
      let(:authorize_params) { { error_reason: "some error" } }
      # let(:request) { super().merge( params: { error_reason: "some error" }) }

      it 'fails with error' do
        expect { subject.callback_phase }.to raise_error(OmniAuth::Strategies::OAuth2::CallbackError)
      end
    end

    context 'when state is not valid' do
      before do
        request.params["state"] = "invalid_state"
        subject.session["omniauth.state"] = "valid_state"
        # subject.options.provider_ignores_state = false
      end

      # it 'fails with csrf_detected' do
      #   expect { subject.callback_phase }.to raise_error(OmniAuth::Strategies::OAuth2::CallbackError, "CSRF detected")
      # end
    end

    context 'when state is valid' do
      before do
        request.params["state"] = "valid_state"
        subject.session["omniauth.state"] = "valid_state"
      end

      it 'does not raise an error' do
        expect { subject.callback_phase }.not_to raise_error
      end
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
end
