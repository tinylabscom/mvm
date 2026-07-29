Feature: No cross-tenant same-page merge

  Same-page merging is confined to one fork family running one sealed image
  for one tenant; any mismatch refuses merging and prevents cross-VM
  co-residency leaks.

  Scenario Outline: page-merge candidates outside one family-image-tenant are refused
    Given a page-merge scope named A for tenant <tenant>, image <image>, family <family>
    And a page-merge scope named B for tenant <other_tenant>, image <other_image>, family <other_family>
    When merge decision is computed between A and B
    Then the merge decision is <decision>

    Examples:
      | tenant | image    | family    | other_tenant | other_image | other_family | decision |
      | t1     | deadbeef | parent-1  | t1           | deadbeef    | parent-1     | Permit   |
      | t1     | deadbeef | parent-1  | t2           | deadbeef    | parent-1     | Refuse   |
      | t1     | deadbeef | parent-1  | t1           | cafef00d    | parent-1     | Refuse   |
      | t1     | deadbeef | parent-1  | t1           | deadbeef    | parent-2     | Refuse   |
