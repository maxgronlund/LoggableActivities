require 'rails_helper'

RSpec.describe Loggable::Activity, type: :model do
  describe 'validations' do
    it 'is invalid without actor' do
      activity = Loggable::Activity.new
      expect(activity).not_to be_valid
      expect(activity.errors[:actor]).to include("can't be blank")
    end

    it 'is invalid without at least one payload' do
      actor = FactoryBot.create(:user)
      activity = Loggable::Activity.new(actor: actor)
      expect(activity).not_to be_valid
      expect(activity.errors[:payloads]).to include('must have at least one payload')
    end

    it 'is valid with actor and at least one payload' do
      actor = FactoryBot.create(:user)
      activity = FactoryBot.build(:loggable_activity, actor: actor)

      payload_attrs = { owner: actor, attrs: { fo: 'bar' }.to_json }
      activity.payloads.build(payload_attrs)

      expect(activity).to be_valid
    end
  end
end
