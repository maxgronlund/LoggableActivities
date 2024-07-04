class User < ApplicationRecord
  include LoggableActivity::Hooks
  has_one :profile, dependent: :destroy
  accepts_nested_attributes_for :profile
  def full_name
    "#{first_name} #{last_name}"
  end

  def authenticate(password)
    password == 'password'
  end
end
