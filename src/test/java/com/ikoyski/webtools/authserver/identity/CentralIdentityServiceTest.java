package com.ikoyski.webtools.authserver.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verifyNoInteractions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

import com.ikoyski.webtools.authserver.identity.CentralIdentityService.FederatedIdentity;
import com.ikoyski.webtools.authserver.identity.CentralIdentityService.FederatedResult;

@ExtendWith(MockitoExtension.class)
class CentralIdentityServiceTest {

    @Mock
    private JdbcTemplate jdbc;

    @InjectMocks
    private CentralIdentityService identities;

    @Test
    void rejectsProvidersThatAreNotEnabled() {
        FederatedResult result = identities.federated(
                new FederatedIdentity("MICROSOFT", "subject-1", "person@example.com", true, "Person", null));

        assertEquals(FederatedResult.Status.INVALID, result.status());
        verifyNoInteractions(jdbc);
    }

    @Test
    void rejectsUnverifiedEmailBeforeCreatingAnIdentity() {
        FederatedResult result = identities.federated(
                new FederatedIdentity("GOOGLE", "subject-1", "person@example.com", false, "Person", null));

        assertEquals(FederatedResult.Status.EMAIL_NOT_VERIFIED, result.status());
        verifyNoInteractions(jdbc);
    }

    @Test
    void rejectsMissingStableProviderSubject() {
        FederatedResult result = identities.federated(
                new FederatedIdentity("GITHUB", " ", "person@example.com", true, "Person", null));

        assertEquals(FederatedResult.Status.INVALID, result.status());
        verifyNoInteractions(jdbc);
    }
}
